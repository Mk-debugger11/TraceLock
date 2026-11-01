"""Cloud providers, used ONLY when TRACELOCK_LLM_PROVIDER=anthropic|openai is set explicitly.

Kept for the knowledge-base seeding workflow (`python -m tracelock.kb.llm --seed`). A key in the
environment alone never selects one, and the local provider never falls back to these.
"""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request

from .base import ChatResult, LLMBadResponse, LLMDisabled, LLMHTTPError, LLMProvider, LLMTimeout, LLMUnavailable


def _post(url: str, body: dict, headers: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise LLMHTTPError(f"HTTP {exc.code} from {url.split('/')[2]}") from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise LLMTimeout(f"{url.split('/')[2]} timed out") from None
        raise LLMUnavailable(f"cannot reach {url.split('/')[2]}") from None
    except (socket.timeout, TimeoutError):
        raise LLMTimeout(f"{url.split('/')[2]} timed out") from None
    except ValueError:
        raise LLMBadResponse("response is not JSON") from None


class _Cloud(LLMProvider):
    key_env = ""

    def __init__(self, model: str, timeout: float = 90.0):
        super().__init__(model)
        self.timeout = timeout

    def check_available(self) -> None:
        if not os.environ.get(self.key_env):
            raise LLMDisabled(f"{self.name} selected but {self.key_env} is not set")

    def _finish(self, text: str, t0: float) -> ChatResult:
        if not text.strip():
            raise LLMBadResponse("empty reply")
        start, end = text.find("{"), text.rfind("}")
        try:
            data = json.loads(text[start:end + 1]) if start >= 0 else None
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise LLMBadResponse("the model reply is not a JSON object")
        return ChatResult(text, data, self.name, self.model, int((time.monotonic() - t0) * 1000))


class AnthropicProvider(_Cloud):
    name, key_env = "anthropic", "ANTHROPIC_API_KEY"

    def chat_json(self, system: str, user: str, schema: dict) -> ChatResult:
        self.check_available()
        t0 = time.monotonic()
        data = _post("https://api.anthropic.com/v1/messages",
                     {"model": self.model, "max_tokens": 1500, "temperature": 0, "system": system,
                      "messages": [{"role": "user", "content": user + "\n\nJSON schema:\n" + json.dumps(schema)}]},
                     {"x-api-key": os.environ[self.key_env], "anthropic-version": "2023-06-01"}, self.timeout)
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        return self._finish(text, t0)


class OpenAIProvider(_Cloud):
    name, key_env = "openai", "OPENAI_API_KEY"

    def chat_json(self, system: str, user: str, schema: dict) -> ChatResult:
        self.check_available()
        t0 = time.monotonic()
        base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")   # vLLM, Groq, OpenRouter, ...
        data = _post(f"{base}/chat/completions",
                     {"model": self.model, "temperature": 0, "response_format": {"type": "json_object"},
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user", "content": user + "\n\nJSON schema:\n" + json.dumps(schema)}]},
                     {"Authorization": f"Bearer {os.environ[self.key_env]}"}, self.timeout)
        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            raise LLMBadResponse("unexpected response shape") from None
        return self._finish(text, t0)

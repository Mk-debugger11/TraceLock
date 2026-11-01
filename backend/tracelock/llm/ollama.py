"""Ollama provider: the model runs in the `ollama` Docker container; TraceLock talks to it over HTTP.

    GET  /api/tags   which models are pulled (availability check, cached for AVAILABILITY_TTL seconds)
    POST /api/chat   {"model", "messages", "stream": false, "format": <JSON schema>, "options": {...}}

Plain urllib (the engine is stdlib-only). Every failure becomes a typed LLMError with a message a
person can act on; nothing here ever raises anything else, and nothing falls back to another provider.
After a connection failure the provider stays "down" for DOWN_SECONDS, so one stopped container
costs one timeout per scan, not one per advisory.
"""
from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

from .base import (ChatResult, LLMBadResponse, LLMHTTPError, LLMModelMissing, LLMProvider, LLMTimeout,
                   LLMUnavailable)
from .settings import LLMSettings

AVAILABILITY_TTL = 30.0
DOWN_SECONDS = 60.0
TAGS_TIMEOUT = 5.0
PULL_HINT = "docker compose exec ollama ollama pull {model}"

_state_lock = threading.Lock()
_down_until: dict[str, float] = {}
_available_until: dict[tuple[str, str], float] = {}


def reset_state() -> None:
    """Forget cached availability (tests, or after `docker compose up`)."""
    with _state_lock:
        _down_until.clear()
        _available_until.clear()


def _same_model(wanted: str, have: str) -> bool:
    norm = lambda m: m if ":" in m else m + ":latest"
    return norm(wanted) == norm(have)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, settings: LLMSettings, urlopen: Optional[Callable] = None):
        super().__init__(settings.model)
        self.settings = settings
        self.base_url = settings.base_url.rstrip("/")
        self._urlopen = urlopen or urllib.request.urlopen
        self._structured = True    # set to False if the server is too old for JSON-schema `format`

    # --- HTTP ---------------------------------------------------------------------------------

    def _request(self, method: str, path: str, body: Optional[dict], timeout: float) -> dict:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
        try:
            with self._urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = json.loads(exc.read().decode("utf-8", errors="replace")).get("error", "")
            except Exception:
                pass
            if exc.code == 404 and "not found" in detail.lower():
                raise LLMModelMissing(f"model {self.model} is not available in Ollama; pull it with: {PULL_HINT.format(model=self.model)}") from None
            raise LLMHTTPError(f"Ollama returned HTTP {exc.code}" + (f": {detail[:200]}" if detail else "")) from None
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise LLMTimeout(f"Ollama at {self.base_url} did not answer within {timeout:.0f}s") from None
            self._mark_down()
            raise LLMUnavailable(f"cannot reach Ollama at {self.base_url} ({reason}); is the container running? "
                                 "docker compose up -d ollama") from None
        except (socket.timeout, TimeoutError):
            raise LLMTimeout(f"Ollama at {self.base_url} did not answer within {timeout:.0f}s") from None
        except (ConnectionError, OSError) as exc:
            self._mark_down()
            raise LLMUnavailable(f"cannot reach Ollama at {self.base_url} ({exc})") from None
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError:
            raise LLMBadResponse("Ollama returned a body that is not JSON") from None
        if not isinstance(parsed, dict):
            raise LLMBadResponse("Ollama returned an unexpected JSON value")
        return parsed

    def _mark_down(self) -> None:
        with _state_lock:
            _down_until[self.base_url] = time.monotonic() + DOWN_SECONDS

    # --- availability -------------------------------------------------------------------------

    def list_models(self) -> list[str]:
        data = self._request("GET", "/api/tags", None, timeout=min(TAGS_TIMEOUT, self.settings.timeout))
        return [m.get("name") or m.get("model") or "" for m in data.get("models", []) if isinstance(m, dict)]

    def check_available(self) -> None:
        now = time.monotonic()
        with _state_lock:
            if _down_until.get(self.base_url, 0.0) > now:
                raise LLMUnavailable(f"Ollama at {self.base_url} was unreachable less than {DOWN_SECONDS:.0f}s ago; skipped")
            if _available_until.get((self.base_url, self.model), 0.0) > now:
                return
        models = self.list_models()
        if not any(_same_model(self.model, m) for m in models):
            raise LLMModelMissing(f"Ollama is running but model {self.model} is not pulled "
                                  f"(have: {', '.join(models) or 'none'}); run: {PULL_HINT.format(model=self.model)}")
        with _state_lock:
            _available_until[(self.base_url, self.model)] = time.monotonic() + AVAILABILITY_TTL

    # --- inference ----------------------------------------------------------------------------

    def chat_json(self, system: str, user: str, schema: dict) -> ChatResult:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": schema if self._structured else "json",
            "keep_alive": self.settings.keep_alive,
            "options": {"temperature": 0, "seed": 7, "num_ctx": self.settings.num_ctx,
                        "num_predict": self.settings.num_predict},
        }
        t0 = time.monotonic()
        try:
            data = self._request("POST", "/api/chat", body, timeout=self.settings.timeout)
        except LLMHTTPError as exc:
            # Servers older than structured outputs reject a schema in `format`; plain JSON mode is still validated by us.
            if self._structured and "format" in str(exc).lower():
                self._structured = False
                return self.chat_json(system, user, schema)
            raise
        latency = int((time.monotonic() - t0) * 1000)
        if data.get("error"):
            raise LLMHTTPError(f"Ollama error: {str(data['error'])[:200]}")
        message = data.get("message") or {}
        text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(text, str) or not text.strip():
            raise LLMBadResponse("Ollama returned an empty reply")
        if data.get("done_reason") == "length":
            raise LLMBadResponse("the reply was cut off at the token limit (raise OLLAMA_NUM_PREDICT or shorten the prompt)")
        try:
            parsed = json.loads(text)
        except ValueError:
            raise LLMBadResponse("the model reply is not valid JSON") from None
        if not isinstance(parsed, dict):
            raise LLMBadResponse("the model reply is not a JSON object")
        ns = 1_000_000
        stats = {k: data.get(k) for k in ("prompt_eval_count", "eval_count") if isinstance(data.get(k), int)}
        for k in ("total_duration", "load_duration", "prompt_eval_duration", "eval_duration"):
            if isinstance(data.get(k), int):
                stats[k.replace("duration", "ms")] = data[k] // ns
        return ChatResult(text=text, data=parsed, provider=self.name, model=data.get("model") or self.model,
                          latency_ms=latency, stats=stats)

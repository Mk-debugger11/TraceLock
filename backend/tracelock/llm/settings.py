"""LLM configuration from environment variables. The only place that reads them.

    TRACELOCK_LLM_ENABLED=true          off by default: deterministic analysis never needs a model
    TRACELOCK_LLM_PROVIDER=ollama       ollama (local, default) | anthropic | openai | none
    OLLAMA_BASE_URL=http://127.0.0.1:11434   FastAPI on the host; http://ollama:11434 inside Docker Compose
    OLLAMA_MODEL=qwen2.5-coder:3b       or qwen2.5-coder:1.5b on a machine with less memory
    OLLAMA_TIMEOUT_SECONDS=120
    OLLAMA_NUM_CTX=4096                 context window per request (prompts are kept well under it)
    OLLAMA_NUM_PREDICT=900              max tokens the model may generate per answer
    OLLAMA_KEEP_ALIVE=10m               how long Ollama keeps the model loaded after a request
    TRACELOCK_LLM_MAX_CONCURRENCY=1     inference requests in flight from this process
    TRACELOCK_LLM_MAX_CALLS_PER_SCAN=12 later advisories stay deterministic once a scan spent its budget
    TRACELOCK_LLM_EXECUTION=docker      label shown in reports ("docker" = the Ollama container)

A cloud provider is used only when TRACELOCK_LLM_PROVIDER names it explicitly. An API key in the
environment never selects one, and a failing local model never falls back to the cloud.
Legacy names still work: TRACELOCK_LLM=ollama enables Ollama, TRACELOCK_LLM_MODEL sets the model.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:3b"
SMALL_OLLAMA_MODEL = "qwen2.5-coder:1.5b"
PROVIDERS = ("ollama", "anthropic", "openai", "none")


def _bool(value: Optional[str], default: bool = False) -> bool:
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(value: Optional[str], default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(str(value).strip())))
    except (TypeError, ValueError):
        return default


def _float(value: Optional[str], default: float, low: float, high: float) -> float:
    try:
        return max(low, min(high, float(str(value).strip())))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class LLMSettings:
    enabled: bool = False
    provider: str = "ollama"
    base_url: str = DEFAULT_OLLAMA_URL
    model: str = DEFAULT_OLLAMA_MODEL
    timeout: float = 120.0
    num_ctx: int = 4096
    num_predict: int = 900
    keep_alive: str = "10m"
    max_concurrency: int = 1
    max_calls_per_scan: int = 12
    execution: str = "docker"

    @property
    def active(self) -> bool:
        return self.enabled and self.provider != "none"

    def describe(self) -> dict:
        """Safe to put in a report: no keys, no secrets."""
        return {"enabled": self.enabled, "provider": self.provider, "model": self.model,
                "execution": self.execution if self.provider == "ollama" else "cloud API",
                "base_url": self.base_url if self.provider == "ollama" else None}


def load_settings(env: Optional[Mapping[str, str]] = None) -> LLMSettings:
    env = os.environ if env is None else env
    legacy = (env.get("TRACELOCK_LLM") or "").strip().lower()
    provider = (env.get("TRACELOCK_LLM_PROVIDER") or legacy or "ollama").strip().lower()
    if provider not in PROVIDERS:
        provider = "none"
    enabled = _bool(env.get("TRACELOCK_LLM_ENABLED"), default=legacy in ("ollama", "anthropic", "openai"))
    base_url = (env.get("OLLAMA_BASE_URL") or "").strip()
    if not base_url:
        host = (env.get("OLLAMA_HOST") or "").strip()   # legacy client-side name; server-style "0.0.0.0:11434" is ignored
        base_url = host if host.startswith(("http://", "https://")) else DEFAULT_OLLAMA_URL
    model = (env.get("OLLAMA_MODEL") or "").strip()
    if provider != "ollama":
        model = (env.get("TRACELOCK_LLM_MODEL") or "").strip() or {"anthropic": "claude-sonnet-5-5", "openai": "gpt-4o-mini"}.get(provider, "")
    elif not model:
        model = (env.get("TRACELOCK_LLM_MODEL") or "").strip() or DEFAULT_OLLAMA_MODEL
    return LLMSettings(
        enabled=enabled,
        provider=provider,
        base_url=base_url.rstrip("/"),
        model=model,
        timeout=_float(env.get("OLLAMA_TIMEOUT_SECONDS"), 120.0, 1.0, 1800.0),
        num_ctx=_int(env.get("OLLAMA_NUM_CTX"), 4096, 1024, 32768),
        num_predict=_int(env.get("OLLAMA_NUM_PREDICT"), 900, 64, 4096),
        keep_alive=(env.get("OLLAMA_KEEP_ALIVE") or "10m").strip(),
        max_concurrency=_int(env.get("TRACELOCK_LLM_MAX_CONCURRENCY"), 1, 1, 8),
        max_calls_per_scan=_int(env.get("TRACELOCK_LLM_MAX_CALLS_PER_SCAN"), 12, 0, 500),
        execution=(env.get("TRACELOCK_LLM_EXECUTION") or "docker").strip(),
    )

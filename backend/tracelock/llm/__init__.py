"""Local LLM support: the model proposes candidate functions, deterministic code verifies, the verdict engine decides.

    from tracelock.llm import get_provider, load_settings
    provider = get_provider()          # None when TRACELOCK_LLM_ENABLED is not true
    provider.check_available()         # raises LLMUnavailable / LLMModelMissing / LLMTimeout
    result, chat = provider.discover_vulnerable_functions(request)   # unverified candidates

The default provider is Ollama running Qwen2.5-Coder in the `ollama` Docker container (see
docker-compose.yml). Nothing in this package can set a verdict or write the trusted knowledge base.
"""
from __future__ import annotations

import threading
from typing import Optional

from .base import (ChatResult, LLMBadResponse, LLMDisabled, LLMError, LLMHTTPError, LLMModelMissing, LLMProvider,
                   LLMTimeout, LLMUnavailable)
from .settings import LLMSettings, load_settings

__all__ = ["ChatResult", "LLMBadResponse", "LLMDisabled", "LLMError", "LLMHTTPError", "LLMModelMissing", "LLMProvider",
           "LLMSettings", "LLMTimeout", "LLMUnavailable", "get_provider", "load_settings", "inference_slot"]

# Tests install a fake provider here: get_provider() returns it regardless of settings.
_provider_override: Optional[LLMProvider] = None
_slots: dict[int, threading.BoundedSemaphore] = {}
_slots_lock = threading.Lock()


def get_provider(settings: Optional[LLMSettings] = None) -> Optional[LLMProvider]:
    """The configured provider, or None when LLM assistance is disabled. Never raises."""
    if _provider_override is not None:
        return _provider_override
    settings = settings or load_settings()
    if not settings.active:
        return None
    if settings.provider == "ollama":
        from .ollama import OllamaProvider
        return OllamaProvider(settings)
    if settings.provider == "anthropic":
        from .cloud import AnthropicProvider
        return AnthropicProvider(settings.model, timeout=settings.timeout)
    if settings.provider == "openai":
        from .cloud import OpenAIProvider
        return OpenAIProvider(settings.model, timeout=settings.timeout)
    return None


def inference_slot(settings: Optional[LLMSettings] = None) -> threading.BoundedSemaphore:
    """Bounds concurrent inference requests from this process (TRACELOCK_LLM_MAX_CONCURRENCY)."""
    n = (settings or load_settings()).max_concurrency
    with _slots_lock:
        return _slots.setdefault(n, threading.BoundedSemaphore(n))

"""Provider interface and the errors every provider raises. No network code here."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .schema import DiscoveryRequest, DiscoveryResult


class LLMError(Exception):
    """Base class. `kind` is what reports show: never a stack trace."""
    kind = "error"


class LLMDisabled(LLMError):
    kind = "disabled"


class LLMUnavailable(LLMError):
    """Connection refused, DNS failure, container stopped."""
    kind = "unavailable"


class LLMTimeout(LLMError):
    kind = "timeout"


class LLMModelMissing(LLMError):
    """The server runs but the model was never pulled into its volume."""
    kind = "model_missing"


class LLMHTTPError(LLMError):
    kind = "http_error"


class LLMBadResponse(LLMError):
    """Empty, truncated, malformed JSON, or a reply that fails the schema."""
    kind = "bad_response"


@dataclass
class ChatResult:
    text: str
    data: dict
    provider: str
    model: str
    latency_ms: int
    stats: dict = field(default_factory=dict)   # prompt/eval token counts and durations, when the server reports them


class LLMProvider(ABC):
    name = "base"

    def __init__(self, model: str):
        self.model = model

    @abstractmethod
    def check_available(self) -> None:
        """Raise LLMUnavailable / LLMModelMissing / LLMTimeout when inference cannot run right now."""

    @abstractmethod
    def chat_json(self, system: str, user: str, schema: dict) -> ChatResult:
        """One chat turn whose reply must be a JSON object matching `schema`. Raises LLMError subclasses."""

    def discover_vulnerable_functions(self, request: "DiscoveryRequest") -> tuple["DiscoveryResult", ChatResult]:
        """Ask for candidate entry points. The result is unverified: callers must verify every candidate."""
        from .prompts import build_discovery_prompt
        from .schema import DISCOVERY_SCHEMA, parse_discovery
        system, user = build_discovery_prompt(request)
        chat = self.chat_json(system, user, DISCOVERY_SCHEMA)
        return parse_discovery(chat.data), chat

"""Typed request/response for LLM function discovery, and strict validation of model output.

The engine is stdlib-only, so these are dataclasses with an explicit validator instead of Pydantic.
The same JSON schema is sent to Ollama as `format` (structured outputs), so a well-behaved model
cannot produce anything else; parse_discovery() still checks every field, because the schema is a
request to the model, not a guarantee.

The response has no verdict field. A reply that tries to state one (verdict, reachable, safe, ...)
is rejected as a whole: the model's job is to name candidate functions, never to judge them.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Optional

from .base import LLMBadResponse

PROMPT_SCHEMA_VERSION = "discovery-v1"
MAX_CANDIDATES = 12
MAX_EVIDENCE = 6
CANDIDATE_KINDS = ("python_public_api", "python_wrapper", "python_internal", "native_registration",
                   "native_function", "pinned_equivalent")
_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,12}$")
_PATH_RE = re.compile(r"^(?![/\\])(?!.*\.\.)[A-Za-z0-9_./+-]{1,300}$")
_VERDICT_WORDS = {"verdict", "reachable", "not_reachable", "uncertain", "safe", "is_safe", "vulnerable",
                  "is_vulnerable", "exploitable", "severity", "decision"}
_TOP_KEYS = {"candidate_functions", "limitations"}
_CANDIDATE_KEYS = {"symbol", "kind", "description", "evidence", "native_target", "reasoning"}

DISCOVERY_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "candidate_functions": {
            "type": "array",
            "maxItems": MAX_CANDIDATES,
            "items": {
                "type": "object",
                "properties": {
                    "symbol": {"type": "string", "description": "dotted Python name, or native function name for native kinds"},
                    "kind": {"type": "string", "enum": list(CANDIDATE_KINDS)},
                    "description": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "maxItems": MAX_EVIDENCE,
                        "items": {"type": "object",
                                  "properties": {"file": {"type": "string"}, "symbol": {"type": "string"}},
                                  "required": ["file", "symbol"]},
                    },
                    "native_target": {"type": "string", "description": "native function this candidate reaches, or empty"},
                    "reasoning": {"type": "string"},
                },
                "required": ["symbol", "kind", "evidence"],
            },
        },
        "limitations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["candidate_functions", "limitations"],
}


@dataclass
class Evidence:
    file: str
    symbol: str


@dataclass
class Candidate:
    symbol: str
    kind: str
    evidence: list[Evidence]
    description: str = ""
    native_target: Optional[str] = None
    reasoning: str = ""          # kept in the cache for debugging; never shown as evidence


@dataclass
class DiscoveryResult:
    candidates: list[Candidate] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    dropped: list[dict] = field(default_factory=list)    # {"index", "symbol", "reason"} for malformed items

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SourceSnippet:
    path: str
    start_line: int
    text: str                    # already numbered "N: code"
    role: str                    # fix_diff | changed_native | registration | python_wrapper | pinned_candidates


@dataclass
class DiscoveryRequest:
    task: str                    # native_entry | pinned_equivalent | python_entry
    ecosystem: str
    package: str
    package_version: str
    advisory_id: str
    summary: str
    fix_commit: str
    changed_files: list[str] = field(default_factory=list)
    changed_functions: list[str] = field(default_factory=list)
    snippets: list[SourceSnippet] = field(default_factory=list)
    allowed_symbols: list[str] = field(default_factory=list)    # when set, candidates must come from this list
    native_targets: list[str] = field(default_factory=list)     # native functions known to reach the changed code


def _has_verdict(obj) -> bool:
    if isinstance(obj, dict):
        return any(str(k).strip().lower() in _VERDICT_WORDS or _has_verdict(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_has_verdict(v) for v in obj)
    return False


def _clean_str(value, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def parse_discovery(data) -> DiscoveryResult:
    """Validate a decoded model reply. Raises LLMBadResponse for a reply that cannot be used at all;
    drops (and records) individual candidates that are malformed."""
    if not isinstance(data, dict):
        raise LLMBadResponse("reply is not a JSON object")
    if _has_verdict(data):
        raise LLMBadResponse("reply contains a verdict-like field; the model may only propose candidates")
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise LLMBadResponse(f"reply has unexpected fields: {sorted(unknown)[:5]}")
    items = data.get("candidate_functions")
    if not isinstance(items, list):
        raise LLMBadResponse("candidate_functions is missing or not a list")
    result = DiscoveryResult(limitations=[_clean_str(x, 300) for x in (data.get("limitations") or []) if isinstance(x, str)][:10])
    seen: set = set()
    for i, item in enumerate(items[:MAX_CANDIDATES * 2]):
        def drop(reason: str) -> None:
            result.dropped.append({"index": i, "symbol": _clean_str(item.get("symbol") if isinstance(item, dict) else "", 200), "reason": reason})
        if not isinstance(item, dict):
            drop("not an object")
            continue
        extra = set(item) - _CANDIDATE_KEYS
        if extra:
            drop(f"unexpected fields {sorted(extra)[:3]}")
            continue
        symbol = _clean_str(item.get("symbol"), 200)
        kind = _clean_str(item.get("kind"), 40)
        if not _SYMBOL_RE.match(symbol):
            drop("symbol is not a dotted identifier")
            continue
        if kind not in CANDIDATE_KINDS:
            drop(f"unknown kind {kind!r}")
            continue
        evidence = []
        for ev in item.get("evidence") or []:
            if not isinstance(ev, dict):
                continue
            path, sym = _clean_str(ev.get("file"), 300), _clean_str(ev.get("symbol"), 200)
            if path and _PATH_RE.match(path) and sym:
                evidence.append(Evidence(path, sym))
        if not evidence:
            drop("no usable source evidence")
            continue
        native = _clean_str(item.get("native_target"), 120) or None
        if native and not re.fullmatch(r"[A-Za-z_]\w*", native):
            drop("native_target is not an identifier")
            continue
        key = (symbol, kind, native)
        if key in seen:
            drop("duplicate")
            continue
        seen.add(key)
        if len(result.candidates) >= MAX_CANDIDATES:
            drop("too many candidates")
            continue
        result.candidates.append(Candidate(symbol=symbol, kind=kind, evidence=evidence[:MAX_EVIDENCE],
                                           description=_clean_str(item.get("description"), 400), native_target=native,
                                           reasoning=_clean_str(item.get("reasoning"), 1200)))
    return result

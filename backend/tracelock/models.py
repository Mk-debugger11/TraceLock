"""Shared data model for TraceLock. THIS FILE IS THE CONTRACT.

Every module reads and writes these dataclasses. Change this file only after
agreeing in the team chat; everyone else's code depends on these field names.
The JSON the CLI emits and the React UI renders is `to_dict(ScanResult)`.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

REACHABLE = "REACHABLE"
NOT_REACHABLE = "NOT_REACHABLE"
UNCERTAIN = "UNCERTAIN"
VERDICTS = (REACHABLE, NOT_REACHABLE, UNCERTAIN)

# Knowledge-base tiers, best to worst.
TIER_CURATED = "curated"
TIER_ECOSYSTEM = "ecosystem_specific"
TIER_FIX_COMMIT = "fix_commit"
TIER_LLM = "llm_verified"
TIER_NONE = "none"


@dataclass
class Dependency:
    name: str                      # normalised PyPI name, lower-case, '-' not '_'
    version: str                   # exact pinned version, e.g. "5.3"
    import_names: list[str] = field(default_factory=list)   # top-level modules: pyyaml -> ["yaml"]
    requires: list[str] = field(default_factory=list)       # names of packages this one requires
    source: str = "requirements"   # requirements | pyproject | venv | lock


@dataclass
class Advisory:
    id: str                        # primary id as OSV gives it (GHSA-..., PYSEC-..., CVE-...)
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    fixed_in: Optional[str] = None
    fix_urls: list[str] = field(default_factory=list)       # references with type FIX
    raw: dict = field(default_factory=dict)                 # full OSV record; dropped from JSON output


@dataclass
class VulnSpec:
    """Which symbols are dangerous for one (advisory, package) pair, and how we know."""
    advisory_id: str
    package: str
    vulnerable_funcs: list[str] = field(default_factory=list)   # internal functions, dotted, from the fix
    entry_api: list[str] = field(default_factory=list)          # public symbols that lead there
    safe_usage: list[dict] = field(default_factory=list)        # [{"func": "yaml.load", "kwarg": "Loader", "safe_values": [...]}]
    tier: str = TIER_NONE
    confidence: float = 0.0
    fix_commit: Optional[str] = None
    evidence_hunks: list[str] = field(default_factory=list)
    notes: str = ""

    def targets(self) -> set[str]:
        return set(self.vulnerable_funcs) | set(self.entry_api)


@dataclass
class CallStep:
    qualname: str                  # app function, e.g. "app.config.parse_config", or the target symbol
    file: str                      # path relative to the scanned root ("" for the target symbol)
    line: int
    code: str                      # the source line, stripped


@dataclass
class Reason:
    kind: str                      # unresolved_call | dynamic | string_ref | star_import | no_function_data | transitive | safe_arg_variable | not_imported | ...
    file: Optional[str]
    line: Optional[int]
    detail: str                    # what we saw
    check: str                     # the one thing a human should verify


@dataclass
class Finding:
    advisory: Advisory
    dependency: Dependency
    spec: VulnSpec
    verdict: str                   # REACHABLE | NOT_REACHABLE | UNCERTAIN
    confidence: float
    path: list[CallStep] = field(default_factory=list)      # entry -> ... -> call site -> target
    entry_kind: Optional[str] = None                        # main | module | route | orphan | None
    reasons: list[Reason] = field(default_factory=list)
    checklist: dict = field(default_factory=dict)           # name -> bool, printed for NOT_REACHABLE
    runtime: Optional[dict] = None                          # {"executed": true, "stack": [...]} from the tracer


@dataclass
class ScanResult:
    root: str
    dependencies: list[Dependency] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def to_dict(result: ScanResult) -> dict:
    """JSON-ready dict; the advisory's raw OSV record is dropped to keep output small."""
    data = asdict(result)
    for finding in data.get("findings", []):
        finding.get("advisory", {}).pop("raw", None)
    return data

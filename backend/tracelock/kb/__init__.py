"""Knowledge base: turns (advisory, dependency) into a VulnSpec. OWNER: Vaibhav.

Tier order: curated -> ecosystem_specific -> fix_commit -> llm_verified -> none.
Tiers merge (a curated safe_usage rule survives when the fix-commit tier adds
functions). `resolve()` is the only function other modules call.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..models import (TIER_CURATED, TIER_ECOSYSTEM, TIER_FIX_COMMIT, TIER_LLM, TIER_NONE,
                      Advisory, Dependency, VulnSpec)
from . import fixdiff, llm

CURATED_PATH = Path(__file__).parent / "curated.json"
_curated_cache: Optional[dict] = None


def _curated() -> dict:
    global _curated_cache
    if _curated_cache is None:
        _curated_cache = json.loads(CURATED_PATH.read_text(encoding="utf-8")) if CURATED_PATH.exists() else {}
    return _curated_cache


def _from_curated(adv: Advisory, dep: Dependency) -> Optional[VulnSpec]:
    table = _curated()
    for key in [adv.id, *adv.aliases]:
        entry = table.get(key)
        if entry and entry.get("package", "").lower() == dep.name.lower():
            return VulnSpec(
                advisory_id=adv.id, package=dep.name,
                vulnerable_funcs=list(entry.get("vulnerable_funcs", [])),
                entry_api=list(entry.get("entry_api", [])),
                safe_usage=list(entry.get("safe_usage", [])),
                tier=TIER_CURATED, confidence=float(entry.get("confidence", 0.95)),
                fix_commit=entry.get("fix_commit"), notes=entry.get("notes", ""),
            )
    return None


def _from_ecosystem_specific(adv: Advisory, dep: Dependency) -> Optional[VulnSpec]:
    """PyPA's proposed format: affected[].ecosystem_specific.imports = [{"attribute": "ImageFont", "modules": ["PIL"]}]."""
    symbols: list[str] = []
    for aff in adv.raw.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != dep.name.lower():
            continue
        for imp in (aff.get("ecosystem_specific") or {}).get("imports", []) or []:
            attr = imp.get("attribute")
            for mod in imp.get("modules", []) or []:
                symbols.append(f"{mod}.{attr}" if attr else mod)
    if not symbols:
        return None
    return VulnSpec(advisory_id=adv.id, package=dep.name, vulnerable_funcs=symbols, entry_api=symbols,
                    tier=TIER_ECOSYSTEM, confidence=0.9, notes="from OSV ecosystem_specific.imports")


def resolve(adv: Advisory, dep: Dependency, lib_src: Optional[Path] = None, offline: bool = False) -> VulnSpec:
    """Best available VulnSpec for this advisory on this dependency. Never raises."""
    spec = _from_curated(adv, dep) or _from_ecosystem_specific(adv, dep)
    if spec is None:
        spec = VulnSpec(advisory_id=adv.id, package=dep.name, tier=TIER_NONE, confidence=0.0)

    # Fix-commit tier adds candidate functions when we have no curated internal list.
    if not spec.vulnerable_funcs and adv.fix_urls and not offline:
        try:
            funcs, hunks, commit = fixdiff.functions_from_fix(adv, dep)
        except Exception as exc:  # network or parse failure: stay honest, do not guess
            funcs, hunks, commit = [], [], None
            spec.notes = (spec.notes + f" fixdiff failed: {exc}").strip()
        if funcs:
            spec.vulnerable_funcs = funcs
            spec.evidence_hunks = hunks
            spec.fix_commit = spec.fix_commit or commit
            if spec.tier == TIER_NONE:
                spec.tier, spec.confidence = TIER_FIX_COMMIT, 0.7

    # LLM tier proposes public entry points; every name must exist in the library source.
    if spec.vulnerable_funcs and not spec.entry_api and lib_src is not None and not offline:
        try:
            proposed = llm.propose_entry_api(adv, dep, spec, lib_src)
        except Exception:
            proposed = []
        verified = [name for name in proposed if llm.symbol_exists(lib_src, dep, name)]
        if verified:
            spec.entry_api = verified
            if spec.tier == TIER_FIX_COMMIT:
                spec.tier, spec.confidence = TIER_LLM, 0.6
    return spec

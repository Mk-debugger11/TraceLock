"""Knowledge base: turns (advisory, dependency) into a VulnSpec. OWNER: Vaibhav.

Tier order: curated -> ecosystem_specific -> fix_commit -> llm_verified -> none.
Tiers merge (a curated safe_usage rule survives when the fix-commit tier adds
functions). `resolve()` is the only function other modules call.

A fix_commit spec is only kept when something maps it to public API (LLM-verified entry_api,
or a library caller from lib_graph.exposure_set); otherwise it is reported as tier none with
the functions kept, so it can produce REACHABLE but never a false NOT_REACHABLE.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..models import (TIER_CURATED, TIER_ECOSYSTEM, TIER_FIX_COMMIT, TIER_LLM, TIER_NATIVE, TIER_NONE,
                      Advisory, Dependency, VulnSpec)
from .. import lib_graph
from . import discovery, fixdiff, llm

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


def resolve(adv: Advisory, dep: Dependency, lib_src: Optional[Path] = None, offline: bool = False,
            session: Optional["discovery.LLMSession"] = None) -> VulnSpec:
    """Best available VulnSpec for this advisory on this dependency. Never raises.

    `session` (one per scan) enables local-LLM assistance where deterministic discovery leaves holes.
    Without it, only the legacy Python entry-API tier can call a model (and only when configured)."""
    spec = _from_curated(adv, dep) or _from_ecosystem_specific(adv, dep)
    if spec is None:
        spec = VulnSpec(advisory_id=adv.id, package=dep.name, tier=TIER_NONE, confidence=0.0)

    # Curated entries carry their fix diff as evidence when data/fixes has it (no network).
    if spec.fix_commit and not spec.evidence_hunks:
        try:
            spec.evidence_hunks = fixdiff.cached_hunks(spec.fix_commit, dep)
        except Exception:
            pass

    # Fix-commit tier adds candidate functions when we have no curated internal list.
    # Offline it still runs from results committed in data/fixes/ (fixdiff never fetches then).
    if not spec.vulnerable_funcs and (adv.fix_urls or adv.raw.get("references")):
        try:
            funcs, hunks, commit = fixdiff.functions_from_fix(adv, dep, offline=offline)
        except Exception as exc:  # network or parse failure: stay honest, do not guess
            funcs, hunks, commit = [], [], None
            spec.notes = (spec.notes + f" fixdiff failed: {exc}").strip()
        if funcs:
            spec.vulnerable_funcs = funcs
            spec.evidence_hunks = hunks
            spec.fix_commit = spec.fix_commit or commit
            if spec.tier == TIER_NONE:
                spec.tier, spec.confidence = TIER_FIX_COMMIT, 0.7
            # Version awareness: functions the fix changes that the pinned version does not define are
            # mapped to pinned equivalents only when their body contains the pre-fix code.
            try:
                extra, vmeta = discovery.python_version_check(adv, dep, funcs, hunks, lib_src, session)
            except Exception as exc:
                extra, vmeta = [], {"error": str(exc)[:200]}
            if vmeta:
                spec.discovery["version_check"] = vmeta
            if extra:
                spec.vulnerable_funcs = sorted(set(spec.vulnerable_funcs) | set(extra))
        elif spec.tier == TIER_NONE:
            # Native fix (C / Rust): map it to Python wrappers deterministically, LLM only for the gaps.
            try:
                found = discovery.native_discovery(adv, dep, lib_src, offline, session)
            except Exception as exc:
                found = None
                spec.notes = (spec.notes + f" native analysis failed: {exc}").strip()
            if found is not None:
                mapping = found["mapping"]
                spec.discovery.update(found["metadata"])
                spec.fix_commit = spec.fix_commit or found["commit"]
                spec.evidence_hunks = spec.evidence_hunks or found["hunks"]
                wrappers = sorted(mapping.wrappers)
                if wrappers or mapping.entry_symbols:
                    spec.vulnerable_funcs = wrappers
                    spec.entry_api = sorted(set(mapping.entry_symbols))
                    spec.tier, spec.confidence = TIER_NATIVE, (0.6 if mapping.complete else 0.5)
                    spec.discovery["chains"] = {k: v for k, v in list(mapping.chains.items())[:60]}
                    spec.notes = (spec.notes + " Native fix mapped through " + ", ".join(
                        sorted({r.py_name for r in mapping.registrations})[:5]) + ".").strip()

    # LLM tier proposes public entry points; every name must exist in the library source
    # ("LLM proposes, AST verifies"). Cache first, so offline runs reuse earlier answers; without
    # the source only names already verified against this exact version are reused.
    if spec.vulnerable_funcs and not spec.entry_api and spec.tier != TIER_NATIVE and session is None:
        verified: list[str] = []
        if lib_src is not None:
            try:
                proposed = llm.propose_entry_api(adv, dep, spec, lib_src, offline=offline)
            except Exception:
                proposed = []
            verified = llm.verify_proposals(lib_src, dep, spec, proposed)
            if proposed:
                llm.record_verified(adv, dep, verified)
        else:
            verified = llm.cached_verified(adv, dep)
        if verified:
            spec.entry_api = verified
            if spec.tier == TIER_FIX_COMMIT:
                spec.tier, spec.confidence = TIER_LLM, 0.6

    # Safety net: fix-commit functions are internal (FullConstructor.construct_python_object_new).
    # Without a public entry point (no curated/LLM entry_api, and no library caller found by
    # lib_graph) an app that only calls yaml.load would look clean, so a missing call proves
    # nothing. Keep the functions (a direct call is still REACHABLE) but report no usable
    # function data, which the verdict engine turns into UNCERTAIN instead of NOT_REACHABLE.
    if spec.tier == TIER_FIX_COMMIT and not spec.entry_api:
        callers: set = set()
        if lib_src is not None:
            try:
                callers = {n for n in lib_graph.exposure_set(lib_src, spec) if n not in spec.vulnerable_funcs}
            except Exception:
                callers = set()
        if not callers:
            spec.tier, spec.confidence = TIER_NONE, 0.0
            spec.notes = (spec.notes + " Fix commit " + (spec.fix_commit or "") + " changes "
                          + ", ".join(spec.vulnerable_funcs[:4]) + ("..." if len(spec.vulnerable_funcs) > 4 else "")
                          + "; no public entry point is known yet, so absence of a call cannot be proven.").strip()
    return spec

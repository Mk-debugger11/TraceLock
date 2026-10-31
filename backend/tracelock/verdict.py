"""Verdict engine: REACHABLE needs one path, NOT_REACHABLE needs the whole checklist, else UNCERTAIN. OWNER: Kartik.

Scaffold status: WORKING MINIMUM of the rules in the plan doc. TODO (Kartik): multi-hop path
selection preferring recognised entry points, kwarg values resolved through bindings instead
of source text, two-level transitive exposure, per-target reasons, trace integration details.
"""
from __future__ import annotations

from typing import Optional

from .app_graph import AppModel, CallSite
from .models import (NOT_REACHABLE, REACHABLE, TIER_NONE, UNCERTAIN, Advisory, CallStep, Dependency,
                     Finding, Reason, VulnSpec)


def _last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _is_hit(cs: CallSite, targets: set[str], last_names: set[str], import_names: list[str]) -> bool:
    if not cs.callee:
        return False
    if cs.callee in targets:
        return True
    top = cs.callee.split(".", 1)[0]
    return top in import_names and cs.last_name in last_names


def _safe_usage(cs: CallSite, spec: VulnSpec) -> tuple[Optional[bool], Optional[str]]:
    """(True=safe, False=unsafe, None=no rule) and a note when the argument is a variable."""
    for rule in spec.safe_usage:
        func = rule.get("func", "")
        if cs.callee == func or (cs.callee and cs.callee.endswith("." + _last(func)) and _last(cs.callee) == _last(func)):
            value = cs.kwargs.get(rule.get("kwarg", ""))
            if value is None:
                return False, None
            if value in rule.get("safe_values", []) or _last(value) in rule.get("safe_values", []):
                return True, None
            if "." in value or value[:1].isupper():
                return False, None  # explicit unsafe loader such as yaml.FullLoader
            return False, f"{rule['kwarg']} comes from variable '{value}' at {cs.file}:{cs.line}; verify it is a safe value"
    return None, None


def _chain(app: AppModel, cs: CallSite, target: str, max_depth: int = 10) -> tuple[list[CallStep], str]:
    """Walk callers upward from the call site to an entry point. Returns (steps entry->target, entry_kind)."""
    steps = [CallStep(cs.caller, cs.file, cs.line, cs.code)]
    seen = {cs.caller}
    current = cs.caller
    entry_kind = None
    for _ in range(max_depth):
        info = app.functions.get(current)
        if info and info.entry_kind:
            entry_kind = info.entry_kind
            break
        callers = [c for c in app.callers_of(current) if c.caller not in seen]
        if not callers:
            break
        callers.sort(key=lambda c: (app.functions.get(c.caller) is None or app.functions[c.caller].entry_kind is None, c.file, c.line))
        nxt = callers[0]
        steps.insert(0, CallStep(nxt.caller, nxt.file, nxt.line, nxt.code))
        seen.add(nxt.caller)
        current = nxt.caller
    if entry_kind is None:
        entry_kind = "orphan"
    steps.append(CallStep(target, "", 0, ""))
    return steps, entry_kind


def decide(app: AppModel, dep: Dependency, adv: Advisory, spec: VulnSpec, exposure: set[str],
           trace: Optional[dict] = None, all_deps: Optional[list[Dependency]] = None) -> Finding:
    targets = spec.targets() | set(exposure)
    last_names = {_last(t) for t in targets}
    import_hits = app.imports_any(dep.import_names)
    imported = bool(import_hits)
    reasons: list[Reason] = []

    # Transitive: some package the app imports requires this one.
    via = []
    for other in all_deps or []:
        if other.name != dep.name and dep.name in [r.lower() for r in other.requires] and app.imports_any(other.import_names):
            via.append(other.name)

    # 1. Runtime confirmation
    if trace and trace.get("executed"):
        return Finding(adv, dep, spec, REACHABLE, 1.0,
                       path=[CallStep(s.get("function", "?"), s.get("file", ""), s.get("line", 0), s.get("code", "")) for s in trace.get("stack", [])],
                       entry_kind="runtime", runtime=trace, reasons=[])

    # 2. Static path
    hits = [cs for cs in app.calls if _is_hit(cs, targets, last_names, dep.import_names)]
    unsafe_hits, safe_notes = [], []
    for cs in hits:
        safe, note = _safe_usage(cs, spec)
        if safe is True:
            continue
        unsafe_hits.append(cs)
        if note:
            safe_notes.append(Reason("safe_arg_variable", cs.file, cs.line, cs.code, note))
    if unsafe_hits:
        cs = unsafe_hits[0]
        path, entry_kind = _chain(app, cs, cs.callee or cs.last_name)
        conf = spec.confidence or 0.5
        return Finding(adv, dep, spec, REACHABLE, round(conf, 2), path=path, entry_kind=entry_kind, reasons=safe_notes,
                       checklist={"call_sites": len(unsafe_hits), "safe_call_sites": len(hits) - len(unsafe_hits)})

    # 3. Uncertainty sources
    for cs in app.calls:
        if cs.callee is None and cs.last_name in last_names:
            reasons.append(Reason("unresolved_call", cs.file, cs.line, cs.code,
                                  f"receiver of .{cs.last_name}() could not be resolved; confirm it is not a {dep.name} object"))
    for m in app.dynamic:
        reasons.append(Reason("dynamic", m.file, m.line, m.detail, f"{m.kind} can reach any symbol; confirm it never targets {dep.name}"))
    for s in app.strings:
        if s.value in targets or s.value in last_names or any(s.value.endswith("." + t) for t in last_names) or s.value in dep.import_names:
            reasons.append(Reason("string_ref", s.file, s.line, s.value, "a string names the vulnerable symbol; check how it is used (template filter, getattr, config)"))
    for mod, f, line in app.star_imports:
        if mod.split(".")[0] in dep.import_names:
            reasons.append(Reason("star_import", f, line, f"from {mod} import *", "star import hides which names are used; replace with explicit imports"))
    if spec.tier == TIER_NONE:
        reasons.append(Reason("no_function_data", None, None, f"{adv.id} names no vulnerable function and has no usable fix commit",
                              "read the advisory and fix manually; treat as affected until then"))
    if not imported and via:
        reasons.append(Reason("transitive", None, None, f"{dep.name} is not imported directly but is required by {', '.join(via)} which the app imports",
                              f"check whether the {via[0]} APIs the app calls reach {dep.name}"))

    checklist = {
        "imported": imported,
        "no_call_to_vulnerable_api": not hits,
        "all_call_sites_safe": not unsafe_hits,
        "no_unresolved_call_with_same_name": not any(r.kind == "unresolved_call" for r in reasons),
        "no_dynamic_markers": not app.dynamic,
        "no_string_reference": not any(r.kind == "string_ref" for r in reasons),
        "no_star_import": not any(r.kind == "star_import" for r in reasons),
        "function_data_available": spec.tier != TIER_NONE,
        "not_transitively_required": not via,
    }
    blocking = [r for r in reasons if r.kind in {"unresolved_call", "dynamic", "string_ref", "star_import", "no_function_data", "transitive"}]

    # 4. Not imported at all (and nothing dynamic that could import it)
    if not imported and not blocking:
        return Finding(adv, dep, spec, NOT_REACHABLE, round(max(spec.confidence, 0.9), 2), entry_kind=None,
                       reasons=[Reason("not_imported", None, None, f"no module in {dep.import_names} is imported by the app", "")], checklist=checklist)

    if blocking:
        return Finding(adv, dep, spec, UNCERTAIN, round(min(spec.confidence or 0.5, 0.6), 2), reasons=reasons, checklist=checklist)

    # 5. Imported, no path, checklist clean
    seen_calls = sorted({f"{cs.callee} ({cs.file}:{cs.line})" for cs in app.calls if cs.callee and cs.callee.split('.')[0] in dep.import_names})[:6]
    detail = "all call sites use safe arguments" if hits else ("calls seen instead: " + ", ".join(seen_calls) if seen_calls else "imported but never called")
    conf = (spec.confidence or 0.7) * (0.9 if any(cs.callee is None for cs in app.calls) else 1.0) * (0.8 if not spec.entry_api and exposure else 1.0)
    return Finding(adv, dep, spec, NOT_REACHABLE, round(conf, 2), reasons=[Reason("no_path", None, None, detail, "")], checklist=checklist)

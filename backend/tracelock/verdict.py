"""Verdict engine: REACHABLE needs one path, NOT_REACHABLE needs the whole checklist, else UNCERTAIN. OWNER: Kartik.

Scaffold status: WORKING MINIMUM of the rules in the plan doc. TODO (Kartik): multi-hop path
selection preferring recognised entry points, kwarg values resolved through bindings instead
of source text, two-level transitive exposure, per-target reasons, trace integration details.
"""
from __future__ import annotations

from dataclasses import replace
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


ENTRY_RANK = {"main": 0, "route": 1, "module": 2, "test": 3, "runtime": 0, "orphan": 9}
REASON_RANK = {"unresolved_call": 0, "string_ref": 1, "star_import": 2, "transitive": 3, "dynamic": 4,
               "no_function_data": 5, "safe_arg_variable": 6, "also_called_at": 7}
MAX_REASONS = 8


def _matches_safe(value: Optional[str], safe_values: list[str]) -> bool:
    return bool(value) and (value in safe_values or _last(value) in safe_values)


def _class_is_safe(app: AppModel, class_qual: str, safe_values: list[str], depth: int = 0) -> Optional[bool]:
    """True if an app class ultimately derives from a safe value, False if from an unsafe library class, None if unknown."""
    info = app.functions.get(class_qual)
    if info is None or not info.is_class or depth > 8:
        return None
    for base in info.bases:
        if _matches_safe(base, safe_values):
            return True
        if base in app.functions:
            inner = _class_is_safe(app, base, safe_values, depth + 1)
            if inner is not None:
                return inner
        elif "." in base:
            return False  # derives from some other library class (e.g. yaml.FullLoader)
    return None


def _safe_usage(cs: CallSite, spec: VulnSpec, app: AppModel) -> tuple[Optional[bool], Optional[str]]:
    """(True=safe, False=unsafe, None=no rule) and a note when the argument is a variable we cannot resolve."""
    for rule in spec.safe_usage:
        func = rule.get("func", "")
        if cs.callee == func or (cs.callee and cs.callee.endswith("." + _last(func)) and _last(cs.callee) == _last(func)):
            kwarg = rule.get("kwarg", "")
            safe_values = rule.get("safe_values", [])
            value = cs.kwargs.get(kwarg)
            if value is None:
                return False, None  # kwarg absent: the library default applies (unsafe for these rules)
            resolved = cs.kwargs_resolved.get(kwarg)
            if _matches_safe(resolved, safe_values) or _matches_safe(value, safe_values):
                return True, None
            if resolved and resolved in app.functions and app.functions[resolved].is_class:
                verdict = _class_is_safe(app, resolved, safe_values)
                if verdict is True:
                    return True, None
                if verdict is False:
                    return False, None
                return False, f"{kwarg}={value} is an app class whose bases could not be resolved ({cs.file}:{cs.line}); verify it derives from a safe loader"
            if resolved or "." in value or value[:1].isupper():
                return False, None  # explicit unsafe value such as yaml.FullLoader
            return False, f"{kwarg} comes from variable '{value}' at {cs.file}:{cs.line}; verify it is a safe value"
    return None, None


def _order_reasons(reasons: list[Reason]) -> list[Reason]:
    """Most specific first, capped so the report stays readable."""
    ordered = sorted(reasons, key=lambda r: (REASON_RANK.get(r.kind, 8), r.file or "", r.line or 0))
    return ordered[:MAX_REASONS]


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
    # Transitive bridges (requests -> urllib3): the exposure set may carry symbols of another package.
    match_import_names = list(dep.import_names) + sorted(getattr(exposure, "import_names", set()))

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
    hits = [cs for cs in app.calls if _is_hit(cs, targets, last_names, match_import_names)]
    # `from yaml import *` then a bare `load(fh)`: the name is unbound in the app, so it can only
    # have come from the star import. Treat it as a hit (over-approximation in the safe direction).
    star_mods = [mod for mod, _f, _l in app.star_imports if mod.split(".")[0] in dep.import_names]
    if star_mods:
        for cs in app.calls:
            if cs.callee is None and cs.receiver is None and cs.last_name in last_names and cs.last_name != "<call>":
                hits.append(replace(cs, callee=f"{star_mods[0]}.{cs.last_name}"))
    unsafe_hits, safe_notes = [], []
    for cs in hits:
        safe, note = _safe_usage(cs, spec, app)
        if safe is True:
            continue
        unsafe_hits.append(cs)
        if note:
            safe_notes.append(Reason("safe_arg_variable", cs.file, cs.line, cs.code, note))
    if unsafe_hits:
        # Show the call site whose chain reaches the best entry point; list the rest as also_called_at.
        chains = [(_chain(app, cs, cs.callee or cs.last_name), cs) for cs in unsafe_hits]
        chains.sort(key=lambda item: (ENTRY_RANK.get(item[0][1], 9), len(item[0][0]), item[1].file, item[1].line))
        (path, entry_kind), best = chains[0]
        # Continue the chain inside the library down to the vulnerable function, when we analysed its source.
        lib_chain = exposure.chain_for(best.callee or best.last_name) if hasattr(exposure, "chain_for") else []
        if len(lib_chain) > 1:
            path = path[:-1] + [CallStep(q, "", 0, "") for q in lib_chain]
        listed = {(best.file, best.line)}
        others = []
        for (_p, _k), cs in chains[1:]:
            if (cs.file, cs.line) not in listed and len(others) < 5:
                listed.add((cs.file, cs.line))
                others.append(Reason("also_called_at", cs.file, cs.line, cs.code, ""))
        conf = spec.confidence or 0.5
        if not imported and via:
            safe_notes.append(Reason("transitive", None, None,
                                     f"{dep.name} is reached through {', '.join(via)}, which the app imports", ""))
            conf *= 0.9
        return Finding(adv, dep, spec, REACHABLE, round(conf, 2), path=path, entry_kind=entry_kind,
                       reasons=_order_reasons(safe_notes + others),
                       checklist={"call_sites": len(unsafe_hits), "safe_call_sites": len(hits) - len(unsafe_hits)})

    # 3. Uncertainty sources
    for cs in app.calls:
        if cs.callee is None and cs.last_name in last_names:
            reasons.append(Reason("unresolved_call", cs.file, cs.line, cs.code,
                                  f"receiver of .{cs.last_name}() could not be resolved; confirm it is not a {dep.name} object"))
    for m in app.dynamic:
        reasons.append(Reason("dynamic", m.file, m.line, m.detail, f"{m.kind} can reach any symbol; confirm it never targets {dep.name}"))
    seen_strings = set()
    for s in app.strings:
        if s.value in targets or s.value in last_names or any(s.value.endswith("." + t) for t in last_names) or s.value in dep.import_names:
            if (s.file, s.value) in seen_strings:
                continue
            seen_strings.add((s.file, s.value))
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
        return Finding(adv, dep, spec, UNCERTAIN, round(min(spec.confidence or 0.5, 0.6), 2),
                       reasons=_order_reasons(reasons), checklist=checklist)

    # 5. Imported, no path, checklist clean
    seen_calls = sorted({f"{cs.callee} ({cs.file}:{cs.line})" for cs in app.calls if cs.callee and cs.callee.split('.')[0] in dep.import_names})[:6]
    detail = "all call sites use safe arguments" if hits else ("calls seen instead: " + ", ".join(seen_calls) if seen_calls else "imported but never called")
    conf = (spec.confidence or 0.7) * (0.9 if any(cs.callee is None for cs in app.calls) else 1.0) * (0.8 if not spec.entry_api and exposure else 1.0)
    return Finding(adv, dep, spec, NOT_REACHABLE, round(conf, 2), reasons=[Reason("no_path", None, None, detail, "")], checklist=checklist)

"""Verdict engine: REACHABLE needs one path, NOT_REACHABLE needs the whole checklist, else UNCERTAIN. OWNER: Kartik.

Scaffold status: WORKING MINIMUM of the rules in the plan doc. TODO (Kartik): multi-hop path
selection preferring recognised entry points, kwarg values resolved through bindings instead
of source text, two-level transitive exposure, per-target reasons, trace integration details.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Optional

from .app_graph import AppModel, CallSite
from .models import (NOT_REACHABLE, REACHABLE, TIER_NATIVE, TIER_NONE, UNCERTAIN, Advisory, CallStep, Dependency,
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
               "dependency_graph_incomplete": 4, "native_mapping_incomplete": 5,
               "no_function_data": 5, "reference": 6, "safe_arg_variable": 6, "also_called_at": 7}
MAX_REASONS = 8
# str/bytes/dict/list methods that appear on unresolved receivers everywhere. In a file that does not import
# the package (nor a package that requires it), an unresolved `x.decode()` is bytes.decode, not jwt.decode, so
# there these never create an unresolved_call reason. In a file that imports it, they still do.
UBIQUITOUS_METHODS = {"decode", "encode", "get", "items", "keys", "values", "update", "pop", "append", "extend",
                      "format", "join", "split", "strip", "lower", "upper", "replace", "read", "write", "close",
                      "copy", "startswith", "endswith", "setdefault", "insert", "remove", "sort", "count", "index"}


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
                # kwarg absent: the library default applies. Rules say whether that default is safe
                # (aiohttp follow_symlinks=False, werkzeug use_debugger=False) or not (yaml.load's FullLoader).
                return bool(rule.get("missing_is_safe", False)), None
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


def _judged_argument(ref, spec: VulnSpec) -> bool:
    """`yaml.load(fh, Loader=yaml.SafeLoader)`: the Loader value is the argument a safe-usage rule judges at
    that call, not a function the app hands out, so on its own it is not a reference hit."""
    if not ref.arg_of or not ref.kwarg:
        return False
    return any(rule.get("kwarg") == ref.kwarg and (ref.arg_of == rule.get("func") or _last(ref.arg_of) == _last(rule.get("func", "")))
               for rule in spec.safe_usage)


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
        # a function registered or stored as a callback is reached through whoever passed it on
        callers += [CallSite(r.caller, r.target, _last(r.target), r.file, r.line, r.code)
                    for r in app.referrers_of(current) if r.caller not in seen]
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


TIER_BASE_NOTE = {
    "curated": "hand-verified knowledge-base entry",
    "ecosystem_specific": "advisory's own affected-imports list",
    "fix_commit": "functions mapped from the fix commit",
    "llm_verified": "LLM-proposed functions, verified against the source",
    "native_mapped": "native (C/Rust) fix mapped to the Python wrappers that call it",
    "none": "no function data",
}


def _no_function_data(adv: Advisory, spec: VulnSpec) -> Reason:
    native = spec.discovery.get("native") or {}
    llm = spec.discovery.get("llm") or {}
    if native.get("changed_functions") or native.get("gaps"):
        gap = (native.get("gaps") or [{}])[0]
        detail = (f"{adv.id} is fixed in native code ({', '.join(c['name'] for c in native.get('changed_functions', [])[:3]) or 'no function identified'}); "
                  f"it could not be mapped to Python: {gap.get('detail', 'no Python-visible path found')[:160]}")
    else:
        detail = f"{adv.id} names no vulnerable function and has no usable fix commit"
    if llm.get("status") in ("unavailable", "model_missing", "timeout"):
        detail += f". Local LLM unavailable ({llm['status']}); deterministic analysis completed"
    return Reason("no_function_data", None, None, detail, "read the advisory and fix manually; treat as affected until then")


def _base_factor(spec: VulnSpec, default: float) -> dict:
    base = spec.confidence or default
    return {"factor": f"function data: {spec.tier}", "effect": f"base {base:.2f}", "note": TIER_BASE_NOTE.get(spec.tier, spec.tier)}


def requirement_chain(dep: Dependency, app: AppModel, all_deps: list[Dependency]) -> tuple[list[str], list[str]]:
    """Walk Requires-Dist from every package the app imports. Returns (chain to dep, or [], packages whose
    requirement metadata is unknown). Unpinned intermediates use the bundled PyPI metadata snapshot."""
    from .deps import requires_for_name
    by_name = {d.name: d for d in all_deps}
    starts = [d.name for d in all_deps if d.name != dep.name and app.imports_any(d.import_names)]
    parent: dict[str, Optional[str]] = {s: None for s in starts}
    queue, unknown = list(starts), []
    while queue:
        cur = queue.pop(0)
        if cur in by_name:
            reqs = [r.lower() for r in by_name[cur].requires]
        else:
            known = requires_for_name(cur)
            if known is None:
                unknown.append(cur)
                continue
            reqs = known
        for r in reqs:
            if r == dep.name:
                chain, node = [dep.name, cur], cur
                while parent.get(node):
                    node = parent[node]
                    chain.append(node)
                return list(reversed(chain)), unknown
            if r not in parent:
                parent[r] = cur
                queue.append(r)
    return [], sorted(set(unknown))


def package_absence(app: AppModel, dep: Dependency, all_deps: list[Dependency],
                    library_imports: Optional[dict]) -> tuple[bool, list[Reason]]:
    """Package-level safety, independent of function data: True only if nothing can load the package.

    1. no app module imports it, and no star import / re-export does (`app.imports_any`)
    2. no package in the app's resolved requirement graph requires it, and that graph is fully known
    3. no imported library's own source imports it (optional imports are not in Requires-Dist)
    4. no dynamic import or other dynamic feature in the app, and no string naming the package
    Any failed condition is returned as a blocking reason."""
    reasons: list[Reason] = []
    if app.imports_any(dep.import_names):
        return False, reasons
    chain, unknown = requirement_chain(dep, app, all_deps)
    if chain:
        reasons.append(Reason("transitive", None, None, f"{dep.name} is required through {' -> '.join(chain)}",
                              f"check whether the {chain[0]} APIs the app calls load {dep.name}"))
    if unknown:
        reasons.append(Reason("dependency_graph_incomplete", None, None,
                              f"requirement metadata unknown for {', '.join(unknown[:5])}; they could require {dep.name}",
                              "pin these packages or scan with a lock file"))
    for d in all_deps:
        if d.name == dep.name or not app.imports_any(d.import_names):
            continue
        tops = (library_imports or {}).get(d.name)
        if tops is None:
            reasons.append(Reason("dependency_graph_incomplete", None, None,
                                  f"source of {d.name} unavailable, so its optional imports of {dep.name} cannot be ruled out",
                                  f"rescan online so {d.name}'s source can be inspected"))
        elif set(tops) & set(dep.import_names):
            reasons.append(Reason("transitive", None, None, f"{d.name}'s own source imports {', '.join(sorted(set(tops) & set(dep.import_names)))}",
                                  f"check whether the {d.name} APIs the app calls load it"))
    for m in app.dynamic:
        reasons.append(Reason("dynamic", m.file, m.line, m.detail, f"{m.kind} could load {dep.name}; confirm it never does"))
    seen = set()
    for s_ in app.strings:
        if s_.value in dep.import_names or any(s_.value.startswith(n + ".") for n in dep.import_names):
            if (s_.file, s_.value) not in seen:
                seen.add((s_.file, s_.value))
                reasons.append(Reason("string_ref", s_.file, s_.line, s_.value, f"a string names {dep.name}; check it is not imported dynamically"))
    return not reasons, reasons


def decide(app: AppModel, dep: Dependency, adv: Advisory, spec: VulnSpec, exposure: set[str],
           trace: Optional[dict] = None, all_deps: Optional[list[Dependency]] = None,
           library_imports: Optional[dict] = None) -> Finding:
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

    # 1. Runtime confirmation: a traced hit whose function belongs to this finding's targets.
    if trace and trace.get("executed"):
        for hit in trace.get("hits", []):
            fn = hit.get("function", "")
            if fn in targets or (fn.split(".")[0] in match_import_names and _last(fn) in last_names):
                # Respect safe-usage rules at runtime: yaml.safe_load calls yaml.load(stream, SafeLoader).
                args = hit.get("args", {})
                if any(_last(fn) == _last(rule.get("func", "")) and _matches_safe(args.get(rule.get("kwarg", "")), rule.get("safe_values", []))
                       for rule in spec.safe_usage):
                    continue
                stack = [CallStep(s.get("function", "?"), s.get("file", ""), s.get("line", 0), s.get("code", "")) for s in hit.get("stack", [])]
                return Finding(adv, dep, spec, REACHABLE, 1.0, path=stack, entry_kind="runtime",
                               runtime={"executed": True, "function": fn, "command": trace.get("command", "")}, reasons=[],
                               confidence_factors=[{"factor": "runtime confirmation", "effect": "1.00",
                                                    "note": f"{fn} executed under the profiler; no static estimate needed"}])

    unpinned = not dep.version
    # 2. Static path
    hits = [cs for cs in app.calls if _is_hit(cs, targets, last_names, match_import_names)]
    # `from yaml import *` then a bare `load(fh)`: the name is unbound in the app, so it can only
    # have come from the star import. Treat it as a hit (over-approximation in the safe direction).
    star_mods = [mod for mod, _f, _l in app.star_imports if mod.split(".")[0] in dep.import_names]
    if star_mods:
        for cs in app.calls:
            if cs.callee is None and cs.receiver is None and cs.last_name in last_names and cs.last_name != "<call>":
                hits.append(replace(cs, callee=f"{star_mods[0]}.{cs.last_name}"))
    # Non-call patterns: a vulnerable class passed as a value (Loader=yaml.FullLoader on any call),
    # or subclassed (class MyLoader(yaml.FullLoader)). Only class-like targets (Capitalised) qualify.
    class_targets = {t for t in targets if _last(t)[:1].isupper()}
    class_lasts = {_last(t) for t in class_targets}
    def _is_class_ref(v: Optional[str]) -> bool:
        return bool(v) and (v in class_targets or (v.split(".")[0] in match_import_names and _last(v) in class_lasts))
    value_hits: list[CallSite] = []
    if class_targets:
        for cs in app.calls:
            if any(_is_class_ref(v) for v in cs.kwargs_resolved.values()) and cs not in hits:
                value_hits.append(cs)
    subclass_hits = [(info, b) for info in app.functions.values() if info.is_class for b in info.bases if _is_class_ref(b)] if class_targets else []

    # A vulnerable function used as a value (`map(yaml.load, xs)`, `partial`, `key=`, a registry, a class
    # attribute, a default argument) can be called by whoever receives it: count it as a call with default
    # arguments, so it goes through the same safe-usage rules (werkzeug's run_simple default is safe, yaml.load's is not).
    ref_hits = []
    for r in app.references:
        cs = CallSite(caller=r.caller, callee=r.target, last_name=_last(r.target), file=r.file, line=r.line, code=r.code)
        if _is_hit(cs, targets, last_names, match_import_names) and not _judged_argument(r, spec):
            ref_hits.append(cs)
    hits += ref_hits
    ref_ids = {id(cs) for cs in ref_hits}
    unsafe_hits, safe_notes = [], []
    for cs in hits:
        safe, note = _safe_usage(cs, spec, app)
        if safe is True:
            continue
        unsafe_hits.append(cs)
        if note:
            safe_notes.append(Reason("safe_arg_variable", cs.file, cs.line, cs.code, note))
    for cs in value_hits:
        safe, _note = _safe_usage(cs, spec, app)
        if safe is not True:
            unsafe_hits.append(cs)
            safe_notes.append(Reason("value_ref", cs.file, cs.line, cs.code, "a vulnerable class is passed as an argument here"))
    if not unsafe_hits and subclass_hits:
        info, base = subclass_hits[0]
        path = [CallStep(info.qualname, info.file, info.line, f"class {_last(info.qualname)}({base})"), CallStep(base, "", 0, "")]
        return Finding(adv, dep, spec, REACHABLE, round((spec.confidence or 0.5) * 0.9, 2), path=path, entry_kind="class definition",
                       reasons=[Reason("subclass", info.file, info.line, f"class {_last(info.qualname)} derives from {base}",
                                       "instances of this class carry the vulnerable behaviour; check where it is instantiated")],
                       checklist={"call_sites": 0, "subclasses": len(subclass_hits)},
                       confidence_factors=[_base_factor(spec, 0.5),
                                           {"factor": "subclass evidence", "effect": "x0.90", "note": "the vulnerable class is inherited, not called directly"}])
    # Explain references only for symbols no real call already shows, and only a few, so they never crowd out other evidence.
    called = {cs.callee for cs in unsafe_hits if id(cs) not in ref_ids}
    for cs in [cs for cs in unsafe_hits if id(cs) in ref_ids and cs.callee not in called][:3]:
        safe_notes.append(Reason("reference", cs.file, cs.line, cs.code,
                                 f"{cs.callee} is passed or stored as a value here; whoever receives it can call it"))
    if unsafe_hits:
        # Show the call site whose chain reaches the best entry point; list the rest as also_called_at.
        chains = [(_chain(app, cs, cs.callee or cs.last_name), cs) for cs in unsafe_hits]
        # A call we can see is better evidence than a reference we assume is called, at the same entry quality.
        chains.sort(key=lambda item: (ENTRY_RANK.get(item[0][1], 9), id(item[1]) in ref_ids, len(item[0][0]), item[1].file, item[1].line))
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
        factors = [_base_factor(spec, 0.5),
                   {"factor": f"entry point: {entry_kind}", "effect": "x1.00",
                    "note": "a resolved call chain from application code to the vulnerable symbol"}]
        if id(best) in ref_ids:
            conf *= 0.9  # the best evidence is a reference: we assume, rather than see, the call
            factors.append({"factor": "reference, not a call", "effect": "x0.90", "note": "the symbol is passed or stored as a value; the call is assumed"})
        if not imported and via:
            safe_notes.append(Reason("transitive", None, None,
                                     f"{dep.name} is reached through {', '.join(via)}, which the app imports", ""))
            conf *= 0.9
            factors.append({"factor": "transitive", "effect": "x0.90", "note": f"reached through {', '.join(via)}"})
        if unpinned:
            safe_notes.append(Reason("version_unpinned", None, None, f"{dep.name} has no pinned version",
                                     f"pin {dep.name} and rescan; the installed version may already be at or past {adv.fixed_in or 'the fix'}"))
            conf *= 0.7
            factors.append({"factor": "version unpinned", "effect": "x0.70", "note": "the installed version may already include the fix"})
        return Finding(adv, dep, spec, REACHABLE, round(conf, 2), path=path, entry_kind=entry_kind,
                       reasons=_order_reasons(safe_notes + others),
                       checklist={"call_sites": len(unsafe_hits), "safe_call_sites": len(hits) - len(unsafe_hits)},
                       confidence_factors=factors)

    # 3. Uncertainty sources
    by_name = {d.name: d for d in all_deps or []}
    package_files = {f for f, _l in import_hits}
    for name in via:
        package_files.update(f for f, _l in app.imports_any(by_name[name].import_names))
    for cs in app.calls:
        if cs.callee is None and cs.last_name in last_names and (cs.last_name not in UBIQUITOUS_METHODS or cs.file in package_files):
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
    if unpinned and imported:
        reasons.append(Reason("version_unpinned", None, None, f"{dep.name} has no pinned version, so this advisory may not apply",
                              f"pin {dep.name} to an exact version and rescan"))
    if spec.tier == TIER_NONE:
        reasons.append(_no_function_data(adv, spec))
    native = spec.discovery.get("native") or {}
    if spec.tier == TIER_NATIVE and not native.get("complete"):
        gaps = native.get("gaps") or []
        first = gaps[0] if gaps else {}
        reasons.append(Reason("native_mapping_incomplete", first.get("file"), first.get("line"),
                              f"the native fix is mapped to Python wrappers, but {native.get('gap_count', len(gaps))} path(s) "
                              f"cannot be followed exactly (e.g. {first.get('kind', 'unknown')}: {first.get('detail', '')[:140]})",
                              "a call to one of the mapped functions is REACHABLE; their absence does not prove safety"))
    # A bridge whose source we analysed and found no path through does not block a verdict when the
    # package is also imported directly; an unanalysed bridge, or a package never imported directly, does.
    bridged = getattr(exposure, "bridged", set())
    unanalysed_via = [v for v in via if v not in bridged]
    if via and (not imported or unanalysed_via):
        how = "is not imported directly but" if not imported else "is imported directly, and is also"
        reasons.append(Reason("transitive", None, None, f"{dep.name} {how} required by {', '.join(via)} which the app imports",
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
    blocking = [r for r in reasons if r.kind in {"unresolved_call", "dynamic", "string_ref", "star_import", "no_function_data",
                                                 "transitive", "version_unpinned", "native_mapping_incomplete"}]

    # 4. Not imported at all (and nothing dynamic that could import it).
    # Missing function data does not matter when the whole package provably never loads, so it stops
    # blocking only after the package-level checks pass (requirement graph, library imports, dynamic loading).
    absent_reasons: list[Reason] = []
    if not imported and all_deps is not None:
        absent, absent_reasons = package_absence(app, dep, all_deps, library_imports)
        if absent and not unpinned:
            blocking = [r for r in blocking if r.kind != "no_function_data"]
        elif spec.tier == TIER_NONE:
            known = {(r.kind, r.detail) for r in reasons}
            extra = [r for r in absent_reasons if (r.kind, r.detail) not in known]
            reasons.extend(extra)
            blocking.extend(extra)
        else:
            # Function data exists: only positive evidence (a requirement chain, a library import) blocks.
            extra = [r for r in absent_reasons if r.kind == "transitive" and (r.kind, r.detail) not in {(x.kind, x.detail) for x in reasons}]
            reasons.extend(extra)
            blocking.extend(extra)
    if not imported and not blocking:
        if spec.tier == TIER_NONE:
            checklist["package_absent_from_dependency_graph"] = True
        return Finding(adv, dep, spec, NOT_REACHABLE, round(max(spec.confidence, 0.9), 2), entry_kind=None,
                       reasons=[Reason("not_imported", None, None, f"no module in {dep.import_names} is imported by the app"
                                       + (", nothing in its requirement graph needs it, and no imported library loads it" if spec.tier == TIER_NONE else ""), "")],
                       checklist=checklist,
                       confidence_factors=[{"factor": "package never imported", "effect": f"floor 0.90",
                                            "note": "independent of function data: no module of the package is imported anywhere and nothing dynamic could import it"}])

    if blocking:
        return Finding(adv, dep, spec, UNCERTAIN, round(min(spec.confidence or 0.5, 0.6), 2),
                       reasons=_order_reasons(reasons), checklist=checklist,
                       confidence_factors=[_base_factor(spec, 0.5),
                                           {"factor": "uncertain verdict", "effect": "cap 0.60",
                                            "note": ", ".join(sorted({r.kind for r in blocking})) + ": the analysis could not resolve everything"}])

    # 5. Imported, no path, checklist clean
    seen_calls = sorted({f"{cs.callee} ({cs.file}:{cs.line})" for cs in app.calls if cs.callee and cs.callee.split('.')[0] in dep.import_names})[:6]
    detail = "all call sites use safe arguments" if hits else ("calls seen instead: " + ", ".join(seen_calls) if seen_calls else "imported but never called")
    has_unresolved = any(cs.callee is None for cs in app.calls)
    derived_only = bool(not spec.entry_api and exposure)
    native_mapped = spec.tier == TIER_NATIVE
    conf = (spec.confidence or 0.7) * (0.9 if has_unresolved else 1.0) * (0.8 if derived_only else 1.0)
    factors = [_base_factor(spec, 0.7), {"factor": "soundness checklist", "effect": "x1.00", "note": f"all {sum(1 for v in checklist.values() if v is True)} checks passed"}]
    if has_unresolved:
        factors.append({"factor": "unresolved calls elsewhere", "effect": "x0.90", "note": "some receivers in the app could not be typed (none share a vulnerable name)"})
    if derived_only:
        factors.append({"factor": "public API derived", "effect": "x0.80", "note": "entry symbols were computed from the library source, not stated by the advisory"})
    if native_mapped:
        conf *= 0.8
        factors.append({"factor": "native mapping", "effect": "x0.80", "note": "C/Rust registrations mapped to Python wrappers with no gaps"})
    return Finding(adv, dep, spec, NOT_REACHABLE, round(conf, 2), reasons=[Reason("no_path", None, None, detail, "")], checklist=checklist,
                   confidence_factors=factors)

"""Library-side analysis: which symbols of a dependency lead to the vulnerable code. OWNER: Kartik.

Given the unpacked source of the dependency (the directory that contains `yaml/` or `jinja2/`)
and a VulnSpec whose `vulnerable_funcs` name internal functions, compute the *exposure set*:
every library function from which a vulnerable function is reachable, plus the names under
which those functions are re-exported (`from .filters import do_xmlattr` in `__init__.py`) or
registered in a dispatch table (`FILTERS = {"xmlattr": do_xmlattr}`, `add_constructor(tag, fn)`).

The verdict engine unions this set into its targets, so an app calling `requests.get` is matched
against a chain `requests.get -> api.request -> Session.request -> Session.send -> ...`.
Over-approximation is deliberate: an unresolved `self.foo()` inside the library matches any
`foo`; a missed edge here would be a false "not reachable", the one failure we must avoid.
"""
from __future__ import annotations

import ast
import hashlib
import pickle
from collections import defaultdict
from pathlib import Path
from typing import Optional

from . import app_graph
from .models import VulnSpec

CACHE_DIR = Path(".tracelock") / "cache" / "graph"
REGISTRY_CALLS = {"add_constructor", "add_multi_constructor", "add_representer", "add_implicit_resolver",
                  "register", "add_filter", "add_test", "add_route", "register_filter"}


def _last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _source_root(lib_src: Path) -> Path:
    """Tolerate being handed an sdist root: prefer the directory that holds the top-level package."""
    lib_src = Path(lib_src)
    if any((p / "__init__.py").exists() for p in lib_src.iterdir() if p.is_dir()):
        return lib_src
    for cand in ("lib3", "src", "lib"):
        for sub in [lib_src / cand, *[d / cand for d in lib_src.iterdir() if d.is_dir()]]:
            if sub.is_dir() and any((p / "__init__.py").exists() for p in sub.iterdir() if p.is_dir()):
                return sub
    for d in lib_src.iterdir():
        if d.is_dir() and any((p / "__init__.py").exists() for p in d.iterdir() if p.is_dir()):
            return d
    return lib_src


def load_model(lib_src: Path) -> app_graph.AppModel:
    """Parse the library once; cache the model under .tracelock/cache/graph/."""
    root = _source_root(lib_src)
    stamp = f"{root.resolve()}|{sum(p.stat().st_mtime_ns for p in root.rglob('*.py'))}"
    key = hashlib.sha1(stamp.encode()).hexdigest()[:16]
    cache = CACHE_DIR / f"{root.name}-{key}.pkl"
    if cache.exists():
        try:
            return pickle.loads(cache.read_bytes())
        except Exception:
            pass
    model = app_graph.build(root)
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(pickle.dumps(model))
    except OSError:
        pass
    return model


def _match_targets(model: app_graph.AppModel, names: list[str]) -> set[str]:
    """Map advisory function names onto the library's qualnames (exact, else by trailing segments)."""
    known = set(model.functions)
    packages = {m.split(".")[0] for m in model.modules}
    out: set[str] = set()
    for name in names:
        if name in known:
            out.add(name)
            continue
        parts = name.split(".")
        if parts[0] not in packages:
            # A symbol of another package (transitive bridge): never fold it onto this library's own
            # functions by suffix; it is reached only through calls whose owner we could not resolve.
            out.add(name)
            continue
        for n in (3, 2, 1):
            suffix = "." + ".".join(parts[-n:])
            cands = {k for k in known if k.endswith(suffix)}
            if cands:
                out.update(cands)
                break
        else:
            out.add(name)  # keep the advisory's name even if we cannot locate it (matched by last name later)
    return out


def _reexport_aliases(root: Path, reachable: set[str]) -> dict[str, str]:
    """`from .x import f` / `from .x import f as g` / `g = x.f` in any __init__.py gives `pkg.g` as an alias of `pkg.x.f`.
    Returns alias -> source qualname."""
    aliases: dict[str, str] = {}
    by_last = defaultdict(set)
    for q in reachable:
        by_last[_last(q)].add(q)
    for init in root.rglob("__init__.py"):
        pkg = ".".join(init.relative_to(root).parent.parts)
        try:
            tree = ast.parse(init.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, OSError):
            continue
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                base_parts = pkg.split(".") if pkg else []
                if node.level:
                    base_parts = base_parts[: max(len(base_parts) - node.level + 1, 0)]
                mod = ".".join(p for p in [*base_parts, node.module or ""] if p)
                for alias in node.names:
                    src = f"{mod}.{alias.name}"
                    public = f"{pkg}.{alias.asname or alias.name}" if pkg else (alias.asname or alias.name)
                    if src in reachable:
                        aliases[public] = src
                    elif by_last.get(alias.name):
                        aliases[public] = sorted(by_last[alias.name])[0]
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                try:
                    value = ast.unparse(node.value)
                except Exception:
                    continue
                public = f"{pkg}.{node.targets[0].id}" if pkg else node.targets[0].id
                if value in reachable:
                    aliases[public] = value
                elif by_last.get(_last(value)):
                    aliases[public] = sorted(by_last[_last(value)])[0]
    return aliases


def _registry_aliases(root: Path, model: app_graph.AppModel, reachable: set[str]) -> set[str]:
    """Dispatch tables: `FILTERS = {"xmlattr": do_xmlattr}` or `Loader.add_constructor("!x", fn)` expose fn under a string name."""
    aliases: set[str] = set()
    last_names = {_last(q) for q in reachable}
    for module, rel in model.modules.items():
        try:
            tree = ast.parse((root / rel).read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str) and isinstance(v, (ast.Name, ast.Attribute)):
                        fn = v.id if isinstance(v, ast.Name) else v.attr
                        if fn in last_names:
                            aliases.add(f"{module}.{k.value}")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in REGISTRY_CALLS:
                if len(node.args) >= 2 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    v = node.args[1]
                    fn = v.id if isinstance(v, ast.Name) else (v.attr if isinstance(v, ast.Attribute) else None)
                    if fn in last_names:
                        aliases.add(f"{module}.{node.args[0].value}")
    return aliases


class ExposureSet(set):
    """A set of dotted names plus, for each, the library-internal chain down to the vulnerable function."""
    def __init__(self, names=(), chains: Optional[dict] = None):
        super().__init__(names)
        self.chains: dict[str, list[str]] = chains or {}
        self.import_names: set[str] = set()   # extra top-level modules the names belong to (transitive bridges)

    def merge_bridge(self, bridge: "ExposureSet", bridge_import_names: list[str]) -> None:
        """Add a bridging package's exposure (e.g. requests functions that call urllib3's entry API),
        stitching each bridge chain onto the inner chain of the symbol it lands on."""
        for name in bridge:
            chain = list(bridge.chains.get(name, [name]))
            inner = self.chain_for(chain[-1])
            if inner:
                chain = chain[:-1] + inner
            self.chains[name] = chain
            self.add(name)
        self.import_names.update(bridge_import_names)

    def chain_for(self, symbol: str) -> list[str]:
        """Chain for an app-side callee such as 'requests.Session.get' (matched exactly, else by trailing segments)."""
        if symbol in self.chains:
            return self.chains[symbol]
        parts = symbol.split(".")
        for n in (3, 2, 1):
            suffix = "." + ".".join(parts[-n:])
            for name, chain in self.chains.items():
                if name.endswith(suffix) and name.split(".")[0] == parts[0]:
                    return chain
        return []


def exposure_set(lib_src: Path, spec: VulnSpec, max_depth: int = 8) -> ExposureSet:
    """All library functions from which any spec.vulnerable_funcs entry is reachable, plus their aliases."""
    if lib_src is None or not spec.vulnerable_funcs:
        return ExposureSet()
    root = _source_root(Path(lib_src))
    model = load_model(root)
    targets = _match_targets(model, spec.vulnerable_funcs)

    by_callee: dict[str, set[str]] = defaultdict(set)
    by_last_unresolved: dict[str, set[str]] = defaultdict(set)
    for cs in model.calls:
        if cs.callee:
            by_callee[cs.callee].add(cs.caller)
        else:
            by_last_unresolved[cs.last_name].add(cs.caller)
    unknown_owner_by_last: dict[str, set[str]] = defaultdict(set)
    for callee, callers in by_callee.items():
        if callee not in model.functions:
            unknown_owner_by_last[_last(callee)] |= callers

    reachable: set[str] = set(targets)
    next_hop: dict[str, str] = {}          # caller -> the callee through which it reaches a target
    frontier = list(targets)
    for _ in range(max_depth):
        nxt = []
        for t in frontier:
            callers = set(by_callee.get(t, ())) | set(by_last_unresolved.get(_last(t), ())) | set(unknown_owner_by_last.get(_last(t), ()))
            for c in callers:
                if c not in reachable:
                    reachable.add(c)
                    next_hop[c] = t
                    nxt.append(c)
        if not nxt:
            break
        frontier = nxt

    reachable = {q for q in reachable if not q.endswith(".<module>")}
    chains: dict[str, list[str]] = {}
    for q in reachable:
        chain, cur, guard = [q], q, 0
        while cur in next_hop and guard < max_depth + 1:
            cur = next_hop[cur]
            chain.append(cur)
            guard += 1
        chains[q] = chain
    reexports = _reexport_aliases(root, reachable)
    for alias, src in reexports.items():
        chains[alias] = chains.get(src, [src])          # the alias *is* the source function
    registry = _registry_aliases(root, model, reachable)
    for a in registry:
        chains.setdefault(a, [a])
    return ExposureSet(reachable | set(reexports) | registry, chains)


def public_api(exposure: set[str]) -> set[str]:
    """Names without a leading-underscore segment: what application code is expected to call."""
    return {q for q in exposure if not any(seg.startswith("_") for seg in q.split("."))}

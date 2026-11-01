"""Deterministic verification of proposed functions. OWNER: Mukul.

Every name an LLM proposes passes through here before it can touch a VulnSpec. A candidate is
accepted only when the pinned version's own source proves it:

  symbol_exists     the dotted name is defined in the pinned package, directly or through an explicit
                    re-export (`from .core import Client` in __init__.py). A name that merely looks
                    plausible, or exists under the same last segment elsewhere, is rejected.
  evidence_files    at least one evidence file the model cites exists in the pinned source; model-invented
                    paths fail this check.
  native_target     (native candidates) the native function exists in the pinned sdist and is connected,
                    through the native call graph, to code the fix changes.
  connected         a call path inside the pinned library goes from the candidate to code that reaches the
                    changed functions (Python exposure set, or a Python function that calls a native
                    registration on the path to the changed native code).
  code_overlap      (pinned equivalents) the candidate's body contains the fix hunk's pre-fix lines.

Checks are strings "passed" / "failed" / "n/a" so reports can show them as they are.
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .. import lib_graph

MAX_FORWARD_DEPTH = 8
MIN_OVERLAP_LINES = 3
MIN_OVERLAP_RATIO = 0.5


@dataclass
class CandidateCheck:
    symbol: str
    kind: str
    native_target: Optional[str] = None
    accepted: bool = False
    resolved: Optional[str] = None
    checks: dict = field(default_factory=dict)
    reason: str = ""
    via: list = field(default_factory=list)     # wrapper functions the accepted path goes through

    def to_dict(self) -> dict:
        return asdict(self)


# --- Python symbols ------------------------------------------------------------------------

def _symbols(lib_src: Path) -> frozenset:
    from .llm import _symbols_in  # cached AST walk of the pinned package
    return _symbols_in(Path(lib_src))


def _exact(root: Path, parts: list[str]) -> bool:
    """Exists with exactly this case (macOS and Windows file systems ignore case: Image.py would match image.py)."""
    cur = root
    for part in parts:
        try:
            if part not in {p.name for p in cur.iterdir()}:
                return False
        except OSError:
            return False
        cur = cur / part
    return cur.is_file()


def _module_file(root: Path, module: str) -> Optional[Path]:
    parts = module.split(".")
    for rel in ([*parts, "__init__.py"], [*parts[:-1], parts[-1] + ".py"]):
        if _exact(root, rel):
            return root.joinpath(*rel)
    return None


def _bindings(path: Path, module: str) -> dict[str, str]:
    """Top-level names a module binds by import or plain assignment -> the dotted name they refer to."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, OSError):
        return {}
    pkg = module if path.name == "__init__.py" else module.rpartition(".")[0]
    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            base = pkg.split(".") if pkg else []
            if node.level:
                base = base[: max(len(base) - node.level + 1, 0)]
            mod = ".".join(p for p in [*base, node.module or ""] if p)
            for a in node.names:
                if a.name != "*":
                    out[a.asname or a.name] = f"{mod}.{a.name}"
        elif isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, (ast.Name, ast.Attribute)):
                try:
                    out[node.targets[0].id] = f"{module}.{ast.unparse(node.value)}" if isinstance(node.value, ast.Name) else ast.unparse(node.value)
                except Exception:
                    pass
    return out


def resolve_python_symbol(lib_src: Path, dotted: str, _depth: int = 0) -> Optional[str]:
    """The qualname `dotted` is defined as in the pinned package, or None. Strict: exact or explicit re-export."""
    if not dotted or _depth > 4:
        return None
    symbols = _symbols(lib_src)
    if dotted in symbols:
        return dotted
    root = Path(lib_src)
    parts = dotted.split(".")
    for i in range(len(parts) - 1, 0, -1):
        module, name, rest = ".".join(parts[:i]), parts[i], parts[i + 1:]
        path = _module_file(root, module)
        if path is None:
            continue
        target = _bindings(path, module).get(name)
        if target and target != dotted:
            found = resolve_python_symbol(lib_src, ".".join([target, *rest]), _depth + 1)
            if found:
                return found
        break   # the longest existing module decides; do not guess further up
    return None


def evidence_check(roots: list[Path], files: list[str]) -> str:
    """'passed' when at least one cited file exists under one of the pinned source roots."""
    for f in files:
        rel = f.lstrip("./")
        for root in roots:
            if root is None:
                continue
            if (Path(root) / rel).is_file():
                return "passed"
            tail = "/".join(rel.split("/")[-2:])
            if tail and any(p.as_posix().endswith(tail) for p in Path(root).rglob(Path(rel).name)):
                return "passed"
    return "failed"


# --- pinned-version equivalence ------------------------------------------------------------

def _norm(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def _significant(line: str) -> bool:
    s = _norm(line)
    return len(s) >= 12 and not s.startswith(("#", '"""', "'''")) and s not in {"return None", "return False", "return True", "else:", "try:"}


def pre_fix_lines(hunks: list[str]) -> list[str]:
    """Deleted and context lines of unified-diff hunks: what the code looked like before the fix."""
    out = []
    for h in hunks:
        for line in h.splitlines():
            if line.startswith(("@@", "+++", "---", "diff ")) or not line[:1] in ("-", " "):
                continue
            if _significant(line[1:]):
                out.append(_norm(line[1:]))
    return list(dict.fromkeys(out))


def python_function_lines(lib_src: Path, qualname: str) -> list[str]:
    model = lib_graph.load_model(lib_src)
    info = model.functions.get(qualname)
    if info is None:
        return []
    root = lib_graph._source_root(Path(lib_src))
    try:
        lines = (root / info.file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [_norm(l) for l in lines[info.line - 1:info.end_line] if _significant(l)]


def overlap_score(pre: list[str], body: list[str]) -> tuple[int, float]:
    if not pre:
        return 0, 0.0
    have = set(body)
    hits = sum(1 for l in set(pre) if l in have)
    return hits, round(hits / len(set(pre)), 2)


def python_equivalents(lib_src: Path, missing: str, hunks: list[str]) -> list[tuple[str, int, float]]:
    """Functions of the pinned package whose body contains the pre-fix code of `missing` (renamed/moved)."""
    pre = pre_fix_lines([h for h in hunks if missing.rsplit(".", 1)[-1] in h] or hunks)
    if len(pre) < MIN_OVERLAP_LINES:
        return []
    model = lib_graph.load_model(lib_src)
    module = missing.rsplit(".", 2)[0]
    funcs = [q for q, i in model.functions.items() if not i.is_class and not q.endswith(".<module>")]
    pool = [q for q in funcs if q.startswith(module + ".")] or [q for q in funcs if q.split(".")[0] == missing.split(".")[0]]
    scored = []
    for q in pool:
        hits, ratio = overlap_score(pre, python_function_lines(lib_src, q))
        if hits >= MIN_OVERLAP_LINES and ratio >= MIN_OVERLAP_RATIO:
            scored.append((q, hits, ratio))
    return sorted(scored, key=lambda s: (-s[2], -s[1], s[0]))[:3]


# --- forward reachability inside the library -------------------------------------------------

def forward_reach(lib_src: Path, start: str, max_depth: int = MAX_FORWARD_DEPTH) -> set[str]:
    """Library functions reachable from `start` (over-approximate: unresolved calls match by last name)."""
    model = lib_graph.load_model(lib_src)
    by_last: dict[str, set] = defaultdict(set)
    for q in model.functions:
        by_last[q.rsplit(".", 1)[-1]].add(q)
    out_edges: dict[str, set] = defaultdict(set)
    for cs in model.calls:
        if cs.callee and cs.callee in model.functions:
            out_edges[cs.caller].add(cs.callee)
            if model.functions[cs.callee].is_class:
                out_edges[cs.caller].add(cs.callee + ".__init__")
        else:
            out_edges[cs.caller] |= by_last.get(cs.last_name, set())
    # a class symbol starts at its constructor and methods
    frontier = {start} | ({q for q in model.functions if q.startswith(start + ".")} if model.functions.get(start, None) and model.functions[start].is_class else set())
    seen = set(frontier)
    for _ in range(max_depth):
        nxt = set()
        for f in frontier:
            for g in out_edges.get(f, ()):
                if g not in seen:
                    seen.add(g)
                    nxt.add(g)
        if not nxt:
            break
        frontier = nxt
    return seen


# --- the checks --------------------------------------------------------------------------------

def verify_python_entry(symbol: str, kind: str, evidence_files: list[str], lib_src: Path, exposure: set) -> CandidateCheck:
    """Python-only advisories: a proposed public entry point must exist and be in the exposure set."""
    chk = CandidateCheck(symbol=symbol, kind=kind)
    resolved = resolve_python_symbol(lib_src, symbol)
    chk.resolved = resolved
    chk.checks["symbol_exists"] = "passed" if resolved else "failed"
    chk.checks["pinned_version"] = chk.checks["symbol_exists"]
    chk.checks["evidence_files"] = evidence_check([Path(lib_src)], evidence_files) if evidence_files else "n/a"
    chain = getattr(exposure, "chain_for", lambda s: [])(resolved) if resolved else []
    chk.checks["connected"] = "passed" if resolved and (resolved in exposure or symbol in exposure or len(chain) > 1) else "failed"
    failed = [k for k, v in chk.checks.items() if v == "failed"]
    chk.accepted = not failed
    chk.reason = "verified against the pinned source" if chk.accepted else "rejected: " + ", ".join(failed)
    return chk


def verify_native_entry(cand, lib_src: Optional[Path], sdist: Optional[Path], index, mapping, import_names: list[str]) -> CandidateCheck:
    """A proposed Python entry point for native code: it must exist, and a library call path must lead from it
    to a Python function that uses a registration whose native chain reaches the candidate's native target."""
    chk = CandidateCheck(symbol=cand.symbol, kind=cand.kind, native_target=cand.native_target)
    files = [e.file for e in cand.evidence]
    chk.checks["evidence_files"] = evidence_check([p for p in (lib_src, sdist) if p], files)
    if cand.kind.startswith("native"):
        ok = index is not None and index.has(cand.symbol)
        chk.checks["native_symbol_exists"] = "passed" if ok else "failed"
        chk.checks["connected"] = "passed" if ok and mapping.closure and (cand.symbol in mapping.closure.hops or cand.symbol in mapping.changed) else "failed"
        chk.accepted = False   # native names never become Python targets on their own
        chk.reason = "native names are recorded as evidence only"
        return chk
    resolved = resolve_python_symbol(lib_src, cand.symbol) if lib_src else None
    chk.resolved = resolved
    chk.checks["symbol_exists"] = "passed" if resolved else "failed"
    chk.checks["pinned_version"] = chk.checks["symbol_exists"]
    clo = mapping.closure
    reached = set(clo.hops) | set(n for n, v in mapping.changed.items() if v.get("pinned")) if clo else set()
    for eqs in mapping.equivalents.values():
        reached |= {n for n, _h, _r in eqs}
    if cand.native_target:
        chk.checks["native_target"] = "passed" if index is not None and index.has(cand.native_target) and cand.native_target in reached else "failed"
    else:
        chk.checks["native_target"] = "n/a"
    sites = dict(mapping.wrappers)
    for q, names in mapping.ambiguous.items():
        sites.setdefault(q, []).extend(names)
    if resolved and sites:
        reach = forward_reach(lib_src, resolved)
        via = sorted(q for q in sites if q in reach)
        if cand.native_target and via and clo:
            regs = {r.py_name: r for r in mapping.registrations}
            via = [q for q in via if any(cand.native_target in clo.chain(regs[n].impl) for n in sites[q] if n in regs)]
        chk.via = via[:8]
        chk.checks["connected"] = "passed" if via else "failed"
    else:
        chk.checks["connected"] = "failed"
    failed = [k for k, v in chk.checks.items() if v == "failed"]
    chk.accepted = not failed
    chk.reason = "verified: a call path in the pinned library leads to the changed native code" if chk.accepted \
        else "rejected: " + ", ".join(failed)
    return chk


def verify_native_equivalent(name: str, missing: str, index, hunks: list[dict], evidence_files: list[str], sdist: Optional[Path]) -> CandidateCheck:
    chk = CandidateCheck(symbol=name, kind="pinned_equivalent", native_target=missing)
    f = index.get(name) if index is not None else None
    chk.checks["native_symbol_exists"] = "passed" if f else "failed"
    chk.checks["evidence_files"] = evidence_check([sdist], evidence_files) if evidence_files and sdist else "n/a"
    pre = [l for h in hunks if missing in h.get("functions", []) for l in h.get("pre_lines", [])]
    hits, ratio = overlap_score(pre, f.lines) if f else (0, 0.0)
    chk.checks["code_overlap"] = "passed" if hits >= MIN_OVERLAP_LINES and ratio >= MIN_OVERLAP_RATIO else "failed"
    failed = [k for k, v in chk.checks.items() if v == "failed"]
    chk.accepted = not failed
    chk.reason = (f"{hits} pre-fix lines ({ratio:.0%}) found in {name}" if f else f"{name} not in the pinned source") \
        + ("" if chk.accepted else "; rejected")
    return chk


def verify_python_equivalent(name: str, missing: str, lib_src: Path, hunks: list[str]) -> CandidateCheck:
    chk = CandidateCheck(symbol=name, kind="pinned_equivalent", native_target=None)
    resolved = resolve_python_symbol(lib_src, name)
    chk.resolved = resolved
    chk.checks["symbol_exists"] = "passed" if resolved else "failed"
    hits, ratio = overlap_score(pre_fix_lines(hunks), python_function_lines(lib_src, resolved)) if resolved else (0, 0.0)
    chk.checks["code_overlap"] = "passed" if hits >= MIN_OVERLAP_LINES and ratio >= MIN_OVERLAP_RATIO else "failed"
    chk.accepted = all(v != "failed" for v in chk.checks.values())
    chk.reason = f"{hits} pre-fix lines ({ratio:.0%}) found in {resolved or name}" + ("" if chk.accepted else "; rejected")
    return chk


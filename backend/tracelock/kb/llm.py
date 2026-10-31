"""LLM tier: propose public entry-API symbols; the caller verifies them against source. OWNER: Vaibhav.

Scaffold status: `symbol_exists` is REAL (AST lookup in the library source);
`propose_entry_api` is a STUB returning []. The LLM never decides a verdict.

What to build (BRIEF_VAIBHAV.md, task 6):
 - Prompt = advisory summary + details + evidence hunks + the list of public functions/classes
   in the package (walk lib_src with ast, collect dotted names without a leading-underscore
   segment, cap at ~400 names). Ask for JSON: {"entry_api": [...], "vulnerable_funcs": [...],
   "reasoning": "..."}.
 - Use whichever API key is available (ANTHROPIC_API_KEY / OPENAI_API_KEY); fall back to a local
   model only if no key. Cache the raw response in tracelock/data/llm_cache/<advisory_id>.json
   and read the cache first, so demos never wait on the network.
 - Return only the entry_api names; kb.resolve() filters them through symbol_exists().
"""
from __future__ import annotations

import ast
from functools import lru_cache
from pathlib import Path

from ..models import Advisory, Dependency, VulnSpec


@lru_cache(maxsize=64)
def _symbols_in(lib_src: Path) -> frozenset:
    """All dotted function/class/method names defined under lib_src (package dir or site-packages-like dir)."""
    names: set[str] = set()
    for py in lib_src.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        rel = py.relative_to(lib_src).with_suffix("")
        parts = list(rel.parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        module = ".".join(parts)

        def walk(node: ast.AST, prefix: str) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    qual = f"{prefix}.{child.name}" if prefix else child.name
                    names.add(qual)
                    walk(child, qual)

        walk(tree, module)
        if module:
            names.add(module)
    return frozenset(names)


def symbol_exists(lib_src: Path, dep: Dependency, dotted: str) -> bool:
    """True if `dotted` (e.g. 'yaml.full_load' or 'jinja2.filters.do_xmlattr') is defined in the library source."""
    symbols = _symbols_in(Path(lib_src))
    if dotted in symbols:
        return True
    # Re-exports: 'yaml.load' may be defined in yaml/__init__.py -> stored as 'yaml.load' already;
    # tolerate 'pkg.sub.name' being asked as 'pkg.name' when name is unique.
    last = dotted.rsplit(".", 1)[-1]
    return any(s.endswith("." + last) and s.startswith(dotted.split(".", 1)[0] + ".") for s in symbols)


def propose_entry_api(adv: Advisory, dep: Dependency, spec: VulnSpec, lib_src: Path) -> list[str]:
    """Ask an LLM which public symbols lead to spec.vulnerable_funcs. Stub: no proposals."""
    return []

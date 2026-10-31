"""Library-side analysis: which public symbols of a dependency lead to the vulnerable code. OWNER: Kartik.

Scaffold status: STUB returning set(). With the stub, the verdict engine works purely from
spec.entry_api (curated). Build (BRIEF_KARTIK.md, task 3):
 1. Reuse app_graph.build() on the library source root (it already resolves relative imports and
    self.method calls) to get calls: caller qualname -> callee dotted / unresolved last_name.
 2. Reverse BFS from every name in spec.vulnerable_funcs (depth <= 8):
    a caller is connected if its resolved callee == target, or if the callee is unresolved and
    its last_name == target's last name (over-approximate on purpose).
 3. Also follow re-exports: `from .filters import do_xmlattr` in jinja2/__init__.py means
    'jinja2.do_xmlattr' is an alias; `load = ...` assignments in __init__ likewise.
 4. Return every reachable function plus the targets themselves, as dotted names rooted at the
    import name (e.g. 'yaml.full_load', 'jinja2.filters.do_xmlattr'). The verdict engine treats
    public ones (no segment starting with '_') as entry API and all of them as targets.
 5. Pickle the library AppModel under .tracelock/cache/graph/<name>-<version>.pkl.
"""
from __future__ import annotations

from pathlib import Path

from .models import VulnSpec


def exposure_set(lib_src: Path, spec: VulnSpec, max_depth: int = 8) -> set[str]:
    """All library functions from which any spec.vulnerable_funcs entry is reachable. Stub: empty."""
    return set()

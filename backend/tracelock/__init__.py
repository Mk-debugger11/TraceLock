"""TraceLock: reachability analysis for known vulnerabilities in Python dependencies.

`scan(root)` is the single entry point used by the CLI, the FastAPI worker and the benchmark.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from . import app_graph, deps, kb, lib_graph, osv, pypi_source, verdict
from .models import ScanResult

__version__ = "0.1.0"


def scan(root: Path, offline: bool = False, trace: Optional[dict] = None, fetch_sources: bool = True) -> ScanResult:
    root = Path(root).resolve()
    t0 = time.time()
    result = ScanResult(root=str(root))

    dependencies = deps.scan_dependencies(root)
    result.dependencies = dependencies
    if not dependencies:
        result.warnings.append("no pinned dependencies found (requirements*.txt with name==version, or pyproject.toml)")

    advisories = osv.lookup(dependencies, offline=offline)
    app = app_graph.build(root)
    result.warnings.extend(app.warnings)

    for dep in dependencies:
        advs = advisories.get(dep.name, [])
        if not advs:
            continue
        lib_src = pypi_source.fetch(dep, offline=offline) if fetch_sources else None
        for adv in advs:
            spec = kb.resolve(adv, dep, lib_src=lib_src, offline=offline)
            exposure = lib_graph.exposure_set(lib_src, spec) if lib_src is not None and spec.vulnerable_funcs else set()
            finding = verdict.decide(app, dep, adv, spec, exposure, trace=trace, all_deps=dependencies)
            result.findings.append(finding)

    result.stats = {
        "seconds": round(time.time() - t0, 2),
        "python_files": len(app.modules),
        "functions": len(app.functions),
        "calls": len(app.calls),
        "dynamic_markers": len(app.dynamic),
        "advisories": sum(len(v) for v in advisories.values()),
    }
    return result

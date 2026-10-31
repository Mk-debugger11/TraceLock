"""TraceLock: reachability analysis for known vulnerabilities in Python dependencies.

`scan(root)` is the single entry point used by the CLI, the FastAPI worker and the benchmark.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from . import app_graph, deps, kb, lib_graph, osv, pypi_source, verdict
from .models import ScanResult, VulnSpec

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

    source_cache: dict[str, Optional[Path]] = {}

    def source_for(d) -> Optional[Path]:
        if d.name not in source_cache:
            try:
                source_cache[d.name] = pypi_source.fetch(d, offline=offline) if fetch_sources else None
            except Exception as exc:  # never let a download problem abort the scan
                result.warnings.append(f"{d.name}=={d.version}: source unavailable ({exc})")
                source_cache[d.name] = None
        return source_cache[d.name]

    # Fetch sources first: for vulnerable packages (library-side analysis) and for every package the app
    # imports, because pypi_source.fetch fills Dependency.requires and that is what the transitive rule reads.
    vulnerable_names = {d.name for d in dependencies if advisories.get(d.name)}
    unimported_vulnerable = [d for d in dependencies if d.name in vulnerable_names and not app.imports_any(d.import_names)]
    for dep in dependencies:
        if dep.name in vulnerable_names or (unimported_vulnerable and app.imports_any(dep.import_names)):
            source_for(dep)

    for dep in dependencies:
        advs = advisories.get(dep.name, [])
        if not advs:
            continue
        lib_src = source_for(dep)
        directly_imported = bool(app.imports_any(dep.import_names))
        bridges = [] if directly_imported else [
            other for other in dependencies
            if other.name != dep.name and dep.name in [r.lower() for r in other.requires] and app.imports_any(other.import_names)
        ]
        for adv in advs:
            spec = kb.resolve(adv, dep, lib_src=lib_src, offline=offline)
            exposure = lib_graph.exposure_set(lib_src, spec) if lib_src is not None and spec.vulnerable_funcs else lib_graph.ExposureSet()
            # Two-level transitive: which public symbols of the importing package reach this package's entry API?
            for other in bridges:
                other_src = source_for(other)
                if other_src is None:
                    continue
                inner_api = sorted(set(spec.entry_api) | lib_graph.public_api(exposure))
                if not inner_api:
                    continue
                bridge_spec = VulnSpec(spec.advisory_id, other.name, vulnerable_funcs=inner_api, tier=spec.tier, confidence=spec.confidence)
                try:
                    bridge = lib_graph.exposure_set(other_src, bridge_spec)
                except Exception as exc:
                    result.warnings.append(f"{other.name}: bridge analysis failed ({exc})")
                    continue
                exposure.merge_bridge(bridge, other.import_names)
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

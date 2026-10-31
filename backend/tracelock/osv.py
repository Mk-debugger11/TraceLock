"""OSV lookup. OWNER: Vaibhav.

Scaffold status: live `POST https://api.osv.dev/v1/querybatch` with a JSON disk
cache under .tracelock/cache/osv/, and an offline fallback that reads
tracelock/data/osv_snapshot.json (same record shape as the OSV API).
TODO (Vaibhav): fill the snapshot for all seed packages, handle pagination,
pull `ecosystem_specific` into Advisory.raw (already there), retries/backoff.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from .models import Advisory, Dependency

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
SNAPSHOT = Path(__file__).parent / "data" / "osv_snapshot.json"
CACHE_DIR = Path(".tracelock") / "cache" / "osv"


def _version_key(v: str):
    try:
        from packaging.version import Version
        return Version(v)
    except Exception:
        parts = []
        for p in v.split("."):
            digits = "".join(ch for ch in p if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)


def version_affected(record: dict, package: str, version: str) -> bool:
    """True if `version` falls inside any ECOSYSTEM range of the record for `package`."""
    v = _version_key(version)
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "PyPI") != "PyPI" or pkg.get("name", "").lower() != package.lower():
            continue
        if version in aff.get("versions", []):
            return True
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            introduced, fixed = None, None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
            lo_ok = introduced in (None, "0") or _version_key(introduced) <= v
            hi_ok = fixed is None or v < _version_key(fixed)
            if lo_ok and hi_ok:
                return True
    return False


def record_to_advisory(record: dict, package: str) -> Advisory:
    fixed_in = None
    for aff in record.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() == package.lower():
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed_in = ev["fixed"]
    fix_urls = [r.get("url", "") for r in record.get("references", []) if r.get("type") == "FIX"]
    return Advisory(
        id=record.get("id", ""),
        aliases=list(record.get("aliases", [])),
        summary=record.get("summary", "") or "",
        details=record.get("details", "") or "",
        fixed_in=fixed_in,
        fix_urls=fix_urls,
        raw=record,
    )


def _load_snapshot() -> dict:
    if SNAPSHOT.exists():
        return json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    return {}


def _cache_path(dep: Dependency) -> Path:
    return CACHE_DIR / f"{dep.name}-{dep.version}.json"


def _fetch_full(vuln_id: str) -> dict:
    with urllib.request.urlopen(OSV_VULN + vuln_id, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _query_live(deps: list[Dependency]) -> dict[str, list[dict]]:
    body = json.dumps({"queries": [
        {"package": {"name": d.name, "ecosystem": "PyPI"}, "version": d.version} for d in deps
    ]}).encode("utf-8")
    req = urllib.request.Request(OSV_QUERYBATCH, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        results = json.loads(resp.read().decode("utf-8")).get("results", [])
    out: dict[str, list[dict]] = {}
    for dep, res in zip(deps, results):
        records = []
        for v in res.get("vulns", []):
            vid = v.get("id")
            if vid:
                records.append(_fetch_full(vid))  # querybatch returns ids only
        out[dep.name] = records
    return out


def lookup(deps: list[Dependency], offline: bool = False) -> dict[str, list[Advisory]]:
    """Map dep.name -> advisories affecting its pinned version. Never raises; falls back to snapshot."""
    result: dict[str, list[Advisory]] = {}
    snapshot = _load_snapshot()
    todo: list[Dependency] = []
    for dep in deps:
        cache = _cache_path(dep)
        if cache.exists():
            result[dep.name] = [record_to_advisory(r, dep.name) for r in json.loads(cache.read_text())]
        else:
            todo.append(dep)
    if todo and not offline:
        try:
            live = _query_live(todo)
            for dep in todo:
                records = live.get(dep.name, [])
                CACHE_DIR.mkdir(parents=True, exist_ok=True)
                _cache_path(dep).write_text(json.dumps(records))
                result[dep.name] = [record_to_advisory(r, dep.name) for r in records]
            todo = []
        except Exception:
            pass  # network failed: use the snapshot below
    for dep in todo:
        records = [r for r in snapshot.get(dep.name, []) if version_affected(r, dep.name, dep.version)]
        result[dep.name] = [record_to_advisory(r, dep.name) for r in records]
    return result

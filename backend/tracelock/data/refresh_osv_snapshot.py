#!/usr/bin/env python3
"""Rebuild tracelock/data/osv_snapshot.json for the seed packages. OWNER: Vaibhav.

    python backend/tracelock/data/refresh_osv_snapshot.py
        Live (preferred): POST https://api.osv.dev/v1/query per package, no version, so every
        advisory for the package is returned; follows next_page_token.

    python backend/tracelock/data/refresh_osv_snapshot.py --upstream PYPA_DIR GHSA_DIR [--meta k=v ...]
        Same records built from checkouts of the two databases osv.dev imports PyPI advisories
        from: github.com/pypa/advisory-database (PYSEC-*, YAML) and
        github.com/github/advisory-database (GHSA-*, JSON, advisories/github-reviewed). Use this
        when api.osv.dev is unreachable.

Both modes keep only records with a PyPI `affected` entry for the package and drop withdrawn
records. Output: {"_comment": ..., "_meta": {...}, "<normalised name>": [record, ...]}.
osv.lookup() filters by version at scan time, so the snapshot holds every version range.
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SEED = [
    "pyyaml", "jinja2", "requests", "urllib3", "pillow", "werkzeug", "flask", "setuptools",
    "pyjwt", "python-multipart", "aiohttp", "black", "cryptography", "certifi", "tqdm",
]
OUT = Path(__file__).resolve().parent / "osv_snapshot.json"
OSV_QUERY = "https://api.osv.dev/v1/query"


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def keep(record: dict, pkg: str) -> bool:
    if record.get("withdrawn"):
        return False
    return any(
        a.get("package", {}).get("ecosystem") == "PyPI" and norm(a.get("package", {}).get("name", "")) == pkg
        for a in record.get("affected", [])
    )


def _post(url: str, body: dict, tries: int = 3) -> dict:
    data = json.dumps(body).encode("utf-8")
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            if attempt == tries - 1:
                raise
            time.sleep(2 ** attempt)
    return {}


def from_api(packages: list[str]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for pkg in packages:
        records, token = [], None
        while True:
            body: dict = {"package": {"name": pkg, "ecosystem": "PyPI"}}
            if token:
                body["page_token"] = token
            page = _post(OSV_QUERY, body)
            records.extend(page.get("vulns", []))
            token = page.get("next_page_token")
            if not token:
                break
        out[pkg] = [r for r in records if keep(r, pkg)]
        print(f"{pkg}: {len(out[pkg])} records", file=sys.stderr)
    return out


def from_upstream(pypa_dir: Path, ghsa_dir: Path, packages: list[str]) -> dict[str, list[dict]]:
    import yaml  # only needed for this mode; BaseLoader keeps every scalar a string, as OSV JSON has them

    wanted = set(packages)
    out: dict[str, dict[str, dict]] = {p: {} for p in packages}

    for path in sorted((pypa_dir / "vulns").glob("*/*.yaml")):
        record = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        for pkg in wanted:
            if keep(record, pkg):
                out[pkg][record["id"]] = record

    for path in sorted((ghsa_dir / "advisories" / "github-reviewed").rglob("GHSA-*.json")):
        text = path.read_text(encoding="utf-8")
        if '"PyPI"' not in text:
            continue
        record = json.loads(text)
        for pkg in wanted:
            if keep(record, pkg):
                out[pkg][record["id"]] = record

    for pkg in packages:
        print(f"{pkg}: {len(out[pkg])} records", file=sys.stderr)
    return {p: list(recs.values()) for p, recs in out.items()}


def main(argv: list[str]) -> int:
    meta: dict = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "packages": SEED}
    for arg in [a for a in argv if a.startswith("--meta=")]:
        key, _, value = arg[len("--meta="):].partition("=")
        meta[key] = value
    argv = [a for a in argv if not a.startswith("--meta=")]
    if argv[:1] == ["--upstream"]:
        records = from_upstream(Path(argv[1]), Path(argv[2]), SEED)
        meta["source"] = "upstream: pypa/advisory-database (PYSEC) + github/advisory-database github-reviewed (GHSA)"
    else:
        records = from_api(SEED)
        meta["source"] = "live: api.osv.dev/v1/query"
    snapshot: dict = {
        "_comment": "Offline fallback for osv.lookup(). Key = normalised PyPI name, value = every OSV record "
                    "(PyPI, not withdrawn) for that package; lookup() filters by the pinned version. "
                    "Regenerate with backend/tracelock/data/refresh_osv_snapshot.py.",
        "_meta": meta,
    }
    for pkg in SEED:
        snapshot[pkg] = sorted(records.get(pkg, []), key=lambda r: r.get("id", ""))
    OUT.write_text(json.dumps(snapshot, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({sum(len(v) for v in records.values())} records)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

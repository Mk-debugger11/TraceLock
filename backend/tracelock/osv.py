"""OSV lookup. OWNER: Vaibhav.

Live `POST https://api.osv.dev/v1/querybatch` (3 tries with backoff) with a JSON disk cache under
.tracelock/cache/osv/, and an offline fallback that reads tracelock/data/osv_snapshot.json (every
OSV record for the seed packages, built by data/refresh_osv_snapshot.py).

Version matching follows the OSV spec's evaluation algorithm (events sorted by version; an event
at or below the pinned version flips the state), so ranges with several introduced/fixed pairs and
`last_affected` events are handled. OSV returns the same advisory under several ids (GHSA-...
and PYSEC-... with the CVE as alias); lookup() merges such twins into one Advisory so each
vulnerability is reported once, with the union of aliases and fix references.
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

from .models import Advisory, Dependency

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
SNAPSHOT = Path(__file__).parent / "data" / "osv_snapshot.json"
CACHE_DIR = Path(".tracelock") / "cache" / "osv"
RETRIES = 3

# PEP 440 subset, enough for PyPI release strings; no third-party dependency so results are the
# same whether or not `packaging` is installed.
_VERSION_RE = re.compile(
    r"^\s*v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>a|alpha|b|beta|c|rc|pre|preview)[-_.]?(?P<pre_n>\d*))?"
    r"(?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d*))?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d*))?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\s*$",
    re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_INF = float("inf")


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _version_key(v: str) -> tuple:
    """Sort key ordered like PEP 440: 1.0.dev1 < 1.0a1 < 1.0rc1 < 1.0 == 1.0.0 < 1.0.post1."""
    m = _VERSION_RE.match(v or "")
    if not m:  # unknown scheme: compare the digit runs, after every well-formed version of equal release
        nums = tuple(int(x) for x in re.findall(r"\d+", v or "")) or (0,)
        return (0, nums, (_INF,), (-_INF,), (_INF,))
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_l, post_present, dev_present = m.group("pre_l"), (m.group("post_n1") or m.group("post_l")) is not None, m.group("dev_l") is not None
    if pre_l:
        pre = (_PRE_RANK[pre_l.lower()], int(m.group("pre_n") or 0))
    elif dev_present and not post_present:
        pre = (-_INF,)  # 1.0.dev1 sorts before 1.0a1
    else:
        pre = (_INF,)
    post = (int(m.group("post_n1") or m.group("post_n2") or 0),) if post_present else (-_INF,)
    dev = (int(m.group("dev_n") or 0),) if dev_present else (_INF,)
    return (int(m.group("epoch") or 0), tuple(release), pre, post, dev)


def _event_value(ev: dict) -> tuple[str, str]:
    for kind in ("introduced", "fixed", "last_affected", "limit"):
        if kind in ev:
            return kind, str(ev[kind])
    return "", ""


def _range_affects(rng: dict, v: tuple) -> tuple[bool, Optional[str]]:
    """(affected?, fixed version that ends the interval containing v) for one ECOSYSTEM range."""
    events = [(_event_value(ev)) for ev in rng.get("events", [])]
    events = [(k, val) for k, val in events if k]
    zero = (0, (0,), (-_INF,), (-_INF,), (-_INF,))  # "0" means 'since the first version'
    keyed = sorted(((zero if (k == "introduced" and val == "0") else _version_key(val)), k, val) for k, val in events)
    affected = False
    for key, kind, _ in keyed:
        if kind == "introduced" and key <= v:
            affected = True
        elif kind == "fixed" and key <= v:
            affected = False
        elif kind == "last_affected" and key < v:
            affected = False
        elif kind == "limit" and key <= v:
            affected = False
    if not affected:
        return False, None
    upper = [val for key, kind, val in keyed if kind == "fixed" and key > v]
    return True, (upper[0] if upper else None)


def _affected_entries(record: dict, package: str) -> list[dict]:
    pkg = normalize_name(package)
    return [a for a in record.get("affected", [])
            if a.get("package", {}).get("ecosystem", "PyPI") == "PyPI"
            and normalize_name(a.get("package", {}).get("name", "")) == pkg]


def _match(record: dict, package: str, version: str) -> tuple[bool, Optional[str]]:
    v = _version_key(version)
    hit, fixed = False, []
    for aff in _affected_entries(record, package):
        if version in aff.get("versions", []):
            hit = True
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            ok, fix = _range_affects(rng, v)
            if ok:
                hit = True
                if fix:
                    fixed.append(fix)
    return hit, (min(fixed, key=_version_key) if fixed else None)


def version_affected(record: dict, package: str, version: str) -> bool:
    """True if `version` falls inside any range (or the explicit versions list) of the record for `package`."""
    return _match(record, package, version)[0]


def record_to_advisory(record: dict, package: str, version: Optional[str] = None) -> Advisory:
    """Advisory for one OSV record. With `version`, fixed_in is the fix that ends the range containing it."""
    fixed_in = None
    if version:
        fixed_in = _match(record, package, version)[1]
    if fixed_in is None:
        for aff in _affected_entries(record, package):
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed_in = ev["fixed"]
    fix_urls = [r.get("url", "") for r in record.get("references", []) if r.get("type") == "FIX"]
    return Advisory(
        id=record.get("id", ""),
        aliases=list(record.get("aliases", []) or []),
        summary=record.get("summary", "") or "",
        details=record.get("details", "") or "",
        fixed_in=fixed_in,
        fix_urls=fix_urls,
        raw=record,
    )


def _primary_rank(record: dict) -> tuple:
    rid = record.get("id", "")
    has_imports = any((a.get("ecosystem_specific") or {}).get("imports") for a in record.get("affected", []))
    order = 0 if rid.startswith("GHSA-") else 1 if rid.startswith("PYSEC-") else 2
    return (0 if has_imports else 1, order, rid)


def merge_aliases(records: list[dict], package: str, version: Optional[str] = None) -> list[Advisory]:
    """One Advisory per vulnerability: records whose id/aliases overlap are merged (GHSA record is primary)."""
    parent = list(range(len(records)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, rec in enumerate(records):
        for key in [rec.get("id", ""), *(rec.get("aliases", []) or [])]:
            if not key:
                continue
            if key in owner:
                parent[find(i)] = find(owner[key])
            else:
                owner[key] = i
    groups: dict[int, list[dict]] = {}
    for i, rec in enumerate(records):
        groups.setdefault(find(i), []).append(rec)

    out = []
    for group in groups.values():
        group.sort(key=_primary_rank)
        adv = record_to_advisory(group[0], package, version)
        for twin in group[1:]:
            for key in [twin.get("id", ""), *(twin.get("aliases", []) or [])]:
                if key and key != adv.id and key not in adv.aliases:
                    adv.aliases.append(key)
            for ref in twin.get("references", []):
                if ref.get("type") == "FIX" and ref.get("url") and ref["url"] not in adv.fix_urls:
                    adv.fix_urls.append(ref["url"])
            adv.summary = adv.summary or twin.get("summary", "") or ""
            adv.details = adv.details or twin.get("details", "") or ""
            if adv.fixed_in is None and version:
                adv.fixed_in = _match(twin, package, version)[1]
        out.append(adv)
    out.sort(key=lambda a: a.id)
    return out


def _load_snapshot() -> dict:
    if SNAPSHOT.exists():
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        return {normalize_name(k): v for k, v in data.items() if not k.startswith("_")}
    return {}


def _cache_path(dep: Dependency) -> Path:
    return CACHE_DIR / f"{dep.name}-{dep.version}.json"


def _urlopen_json(req, timeout: int) -> dict:
    """GET/POST with RETRIES attempts and exponential backoff (0.5s, 1s, ...); raises the last error."""
    last: Exception = RuntimeError("no attempt")
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # URLError, HTTPError, timeout, bad JSON
            last = exc
            if attempt < RETRIES - 1:
                time.sleep(0.5 * (2 ** attempt))
    raise last


def _fetch_full(vuln_id: str) -> dict:
    return _urlopen_json(OSV_VULN + vuln_id, timeout=20)


def _query_live(deps: list[Dependency]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {d.name: [] for d in deps}
    queries = [{"package": {"name": d.name, "ecosystem": "PyPI"}, "version": d.version} for d in deps]
    pending = list(range(len(deps)))
    tokens: dict[int, str] = {}
    while pending:  # follow next_page_token per query until every query is exhausted
        batch = []
        for i in pending:
            q = dict(queries[i])
            if i in tokens:
                q["page_token"] = tokens[i]
            batch.append(q)
        body = json.dumps({"queries": batch}).encode("utf-8")
        req = urllib.request.Request(OSV_QUERYBATCH, data=body, headers={"Content-Type": "application/json"})
        results = _urlopen_json(req, timeout=30).get("results", [])
        next_pending = []
        for i, res in zip(pending, results):
            for v in res.get("vulns", []) or []:
                vid = v.get("id")
                if vid:
                    out[deps[i].name].append(_fetch_full(vid))  # querybatch returns ids only
            if res.get("next_page_token"):
                tokens[i] = res["next_page_token"]
                next_pending.append(i)
        pending = next_pending
    return out


def lookup(deps: list[Dependency], offline: bool = False) -> dict[str, list[Advisory]]:
    """Map dep.name -> advisories affecting its pinned version. Never raises; falls back to snapshot."""
    result: dict[str, list[Advisory]] = {}
    todo: list[Dependency] = []
    for dep in deps:
        cache = _cache_path(dep)
        if cache.exists():
            try:
                records = json.loads(cache.read_text(encoding="utf-8"))
                result[dep.name] = merge_aliases([r for r in records if not r.get("withdrawn")], dep.name, dep.version)
                continue
            except (OSError, ValueError):
                pass  # unreadable cache: refetch
        todo.append(dep)
    if todo and not offline:
        try:
            live = _query_live(todo)
            for dep in todo:
                records = live.get(dep.name, [])
                try:
                    CACHE_DIR.mkdir(parents=True, exist_ok=True)
                    _cache_path(dep).write_text(json.dumps(records), encoding="utf-8")
                except OSError:
                    pass
                result[dep.name] = merge_aliases([r for r in records if not r.get("withdrawn")], dep.name, dep.version)
            todo = []
        except Exception as exc:
            print(f"tracelock: OSV live lookup failed after {RETRIES} tries ({exc}); using the bundled snapshot",
                  file=sys.stderr)
    if todo:
        snapshot = _load_snapshot()
        for dep in todo:
            if dep.name not in snapshot:
                print(f"tracelock: no offline OSV data for {dep.name}=={dep.version}; it is not checked",
                      file=sys.stderr)
            records = [r for r in snapshot.get(dep.name, [])
                       if not r.get("withdrawn") and version_affected(r, dep.name, dep.version)]
            result[dep.name] = merge_aliases(records, dep.name, dep.version)
    return result

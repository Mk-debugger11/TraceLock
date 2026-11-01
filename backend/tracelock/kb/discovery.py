"""Function discovery for advisories whose fix the Python fix-commit tier cannot map. OWNER: Mukul.

    deterministic first:  native.py maps changed C/Rust functions to Python wrappers;
                          verify.python_equivalents() finds renamed/moved Python functions
    LLM where it helps:   only for the holes deterministic analysis leaves (a changed function missing from
                          the pinned version, registrations no Python code visibly uses); the local model
                          proposes candidates, verify.py accepts or rejects each one
    output:               metadata for spec.discovery (what ran, what was suggested, verified, rejected)

LLMSession is created once per scan: one availability check, a call budget, bounded concurrency, and
a per-request cache keyed by everything that affects the answer:

    ecosystem + package + version + advisory + fix commit + source hash + model + prompt schema version

Cache files live in .tracelock/cache/llm/discovery/<key>.json. Successful answers and well-formed but
invalid answers are cached (the model is run at temperature 0 with a fixed seed, so asking again gives
the same reply); timeouts and connection failures are never cached. A per-key lock (thread + file lock)
makes concurrent scans that need the same answer wait for one inference instead of running two.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .. import llm as llm_pkg
from .. import native, pypi_source
from ..llm.base import LLMError
from ..llm.schema import PROMPT_SCHEMA_VERSION, DiscoveryRequest, SourceSnippet
from ..models import Advisory, Dependency
from . import fixdiff, verify

logger = logging.getLogger(__name__)

CACHE_DIR = Path(".tracelock") / "cache" / "llm" / "discovery"
DATA_CACHE = Path(__file__).resolve().parent.parent / "data" / "llm_cache" / "discovery"
NATIVE_COMMITS = Path(".tracelock") / "cache" / "native" / "commits"
MAX_HUNKS_IN_PROMPT = 3
_key_locks: dict[str, threading.Lock] = {}
_key_locks_guard = threading.Lock()


# --- session --------------------------------------------------------------------------------

class LLMSession:
    """Per-scan LLM state. Safe to create when the LLM is disabled (every ask() then reports 'disabled')."""

    def __init__(self, settings=None, provider=None):
        self.settings = settings or llm_pkg.load_settings()
        self.provider = provider if provider is not None else llm_pkg.get_provider(self.settings)
        self.calls = 0
        self.cache_hits = 0
        self.failures: dict[str, int] = {}
        self.latencies: list[int] = []
        self.unavailable: Optional[str] = None
        self.unavailable_kind: Optional[str] = None
        self.suggested = self.verified = self.rejected = 0

    @property
    def enabled(self) -> bool:
        return self.provider is not None

    def describe(self) -> dict:
        d = self.settings.describe()
        if self.provider is not None:
            d.update(provider=self.provider.name, model=self.provider.model)
        return d

    def status(self) -> dict:
        lat = sorted(self.latencies)
        return {**self.describe(), "enabled": self.enabled, "inference_calls": self.calls, "cache_hits": self.cache_hits,
                "failures": dict(self.failures), "unavailable": self.unavailable,
                "candidates_suggested": self.suggested, "candidates_verified": self.verified,
                "candidates_rejected": self.rejected,
                "latency_ms": {"count": len(lat), "median": lat[len(lat) // 2] if lat else None, "max": lat[-1] if lat else None}}

    def ask(self, request: DiscoveryRequest, identity: dict) -> tuple[Optional[object], dict]:
        """(DiscoveryResult or None, meta). meta["status"]: disabled | cached | used | unavailable | model_missing |
        timeout | bad_response | http_error | skipped_budget."""
        meta = {**self.describe(), "task": request.task}
        if self.provider is None:
            return None, {**meta, "status": "disabled"}
        key = cache_key({**identity, "model": self.provider.model, "provider": self.provider.name,
                         "task": request.task, "schema": PROMPT_SCHEMA_VERSION})
        meta["cache_key"] = key
        entry = read_cache(key)
        if entry is not None:
            self.cache_hits += 1
            return _result_from_entry(entry), {**meta, "status": "cached", "cached_status": entry.get("status"),
                                               "latency_ms": entry.get("latency_ms"), "created_at": entry.get("created_at")}
        if self.unavailable:
            return None, {**meta, "status": self.unavailable_kind or "unavailable", "detail": self.unavailable}
        if self.calls >= self.settings.max_calls_per_scan:
            return None, {**meta, "status": "skipped_budget",
                          "detail": f"this scan already made {self.calls} inference calls (TRACELOCK_LLM_MAX_CALLS_PER_SCAN)"}
        with _key_lock(key):
            entry = read_cache(key)   # another scan may have answered while we waited
            if entry is not None:
                self.cache_hits += 1
                return _result_from_entry(entry), {**meta, "status": "cached", "cached_status": entry.get("status")}
            try:
                self.provider.check_available()
            except LLMError as exc:
                self.unavailable, self.unavailable_kind = str(exc), exc.kind
                self.failures[exc.kind] = self.failures.get(exc.kind, 0) + 1
                logger.warning("local LLM unavailable: %s", exc)
                return None, {**meta, "status": exc.kind, "detail": str(exc)}
            self.calls += 1
            t0 = time.monotonic()
            try:
                with llm_pkg.inference_slot(self.settings):
                    result, chat = self.provider.discover_vulnerable_functions(request)
            except LLMError as exc:
                self.failures[exc.kind] = self.failures.get(exc.kind, 0) + 1
                logger.warning("LLM discovery for %s failed (%s): %s", identity.get("advisory_id"), exc.kind, exc)
                if exc.kind == "bad_response":
                    write_cache(key, {**identity, "status": "invalid", "error": str(exc), "provider": self.provider.name,
                                      "model": self.provider.model, "latency_ms": int((time.monotonic() - t0) * 1000)})
                if exc.kind in ("unavailable", "model_missing"):
                    self.unavailable, self.unavailable_kind = str(exc), exc.kind
                return None, {**meta, "status": exc.kind, "detail": str(exc)}
            self.latencies.append(chat.latency_ms)
            write_cache(key, {**identity, "status": "ok", "provider": chat.provider, "model": chat.model,
                              "latency_ms": chat.latency_ms, "stats": chat.stats, "result": result.to_dict(),
                              "raw_reply": chat.text[:6000]})
            return result, {**meta, "status": "used", "latency_ms": chat.latency_ms, "stats": chat.stats}

    def count(self, checks: list) -> None:
        self.suggested += len(checks)
        self.verified += sum(1 for c in checks if c.accepted)
        self.rejected += sum(1 for c in checks if not c.accepted)


@contextmanager
def _key_lock(key: str):
    with _key_locks_guard:
        lock = _key_locks.setdefault(key, threading.Lock())
    with lock:
        handle = None
        try:
            import fcntl  # POSIX only; on other systems the thread lock still prevents duplicates in-process
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            handle = open(CACHE_DIR / f"{key}.lock", "w")
            fcntl.flock(handle, fcntl.LOCK_EX)
        except (ImportError, OSError):
            handle = None
        try:
            yield
        finally:
            if handle is not None:
                try:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_UN)
                except (ImportError, OSError):
                    pass
                handle.close()


# --- cache ----------------------------------------------------------------------------------

def cache_key(identity: dict) -> str:
    return hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:24]


def read_cache(key: str) -> Optional[dict]:
    for base in (DATA_CACHE, CACHE_DIR):
        path = base / f"{key}.json"
        if path.exists():
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if entry.get("status") in ("ok", "invalid"):
                return entry
    return None


def write_cache(key: str, entry: dict) -> None:
    entry = {**entry, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_DIR / f".{key}.tmp"
        tmp.write_text(json.dumps(entry, indent=1, sort_keys=True), encoding="utf-8")
        tmp.replace(CACHE_DIR / f"{key}.json")
    except OSError:
        pass


def record_verification(key: Optional[str], checks: list) -> None:
    """Store the verification outcome next to the cached answer (audit trail; never read back as trust)."""
    if not key:
        return
    path = CACHE_DIR / f"{key}.json"
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry["verification"] = [c.to_dict() for c in checks]
        path.write_text(json.dumps(entry, indent=1, sort_keys=True), encoding="utf-8")
    except (OSError, ValueError):
        pass


def _result_from_entry(entry: dict):
    from ..llm.schema import parse_discovery
    if entry.get("status") != "ok":
        return None
    raw = entry.get("result") or {}
    try:
        return parse_discovery({"candidate_functions": [
            {k: v for k, v in c.items() if k in ("symbol", "kind", "description", "evidence", "native_target", "reasoning")}
            for c in raw.get("candidates", [])], "limitations": raw.get("limitations", [])})
    except LLMError:
        return None


# --- native discovery -----------------------------------------------------------------------

def _diff_text(owner: str, repo: str, sha: str, offline: bool) -> Optional[str]:
    for path in (fixdiff.DATA_FIXES / f"{sha}.diff", fixdiff.CACHE_DIR / f"{sha}.diff"):
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
    if offline:
        return None
    try:
        text = fixdiff._get(f"https://github.com/{owner}/{repo}/commit/{sha}.diff", timeout=60).decode("utf-8", errors="replace")
    except Exception:
        return None
    try:
        fixdiff.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (fixdiff.CACHE_DIR / f"{sha}.diff").write_text(text, encoding="utf-8")
    except OSError:
        pass
    return text


def _changes_for_commit(owner: str, repo: str, sha: str, diff_text: str, offline: bool) -> dict:
    cache = NATIVE_COMMITS / f"{sha}.json"
    if cache.exists():
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except ValueError:
            pass

    def prefix(path: str) -> Optional[str]:
        if offline:
            return None
        source, _how = fixdiff._prefix_source(owner, repo, sha, path)
        return source

    result = native.changed_functions(diff_text, prefix)
    result["commit_url"] = f"https://github.com/{owner}/{repo}/commit/{sha}"
    if not offline or any(f["how"] == "prefix_source" for f in result["files"]):
        try:
            NATIVE_COMMITS.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(result, indent=1), encoding="utf-8")
        except OSError:
            pass
    return result


def native_changes(adv: Advisory, offline: bool) -> dict:
    """Merged native changes of every fix commit of the advisory: {"files", "functions", "hunks", "commits"}."""
    merged: dict = {"files": [], "functions": {}, "hunks": [], "commits": []}
    for owner, repo, sha in fixdiff.candidate_commits(adv, offline):
        text = _diff_text(owner, repo, sha, offline)
        if not text:
            continue
        ch = _changes_for_commit(owner, repo, sha, text, offline)
        if not ch.get("files"):
            continue
        merged["commits"].append(ch.get("commit_url"))
        merged["files"].extend(ch["files"])
        for name, info in ch["functions"].items():
            merged["functions"].setdefault(name, info)
        merged["hunks"].extend(ch["hunks"])
    return merged


def _check_label(passed: bool, failed: bool) -> str:
    return "passed" if passed else ("failed" if failed else "not run")


def native_discovery(adv: Advisory, dep: Dependency, lib_src: Optional[Path], offline: bool,
                     session: Optional[LLMSession]) -> Optional[dict]:
    """None when the advisory's fix changes no native code. Otherwise a dict:
        mapping (NativeMapping), metadata (for spec.discovery), commit, hunks (evidence)."""
    changes = native_changes(adv, offline)
    if not changes["files"]:
        return None
    meta: dict = {"method": "deterministic", "native": {}, "llm": None}
    commit = changes["commits"][0] if changes["commits"] else None
    hunks = [f"{h['path']}\n{h['text']}" for h in changes["hunks"]][:12]
    sdist = pypi_source.fetch_sdist(dep, offline=offline)
    if sdist is None:
        mapping = native.NativeMapping()
        mapping.changed = {k: {**v, "pinned": None} for k, v in changes["functions"].items()}
        mapping.gaps.append(native.Gap("no_native_source", f"the {dep.name}=={dep.version} sdist (its C/Rust source) is not "
                                       "available" + (" offline" if offline else "") + "; the changed native code cannot be mapped"))
        meta["native"] = mapping.summary()
        return {"mapping": mapping, "metadata": meta, "commit": commit, "hunks": hunks}
    index = native.load_index(sdist)
    mapping = native.map_to_python(index, changes, lib_src, dep.import_names)
    meta["native"] = {**mapping.summary(), "source_files_indexed": index.files}

    # --- LLM assistance for what deterministic mapping could not settle -------------------------
    session = session or LLMSession()
    missing = [n for n, v in mapping.changed.items() if v.get("pinned") is False and n not in mapping.equivalents]
    need_entry = bool(mapping.closure) and not mapping.wrappers and not mapping.entry_symbols
    task = "pinned_equivalent" if missing else ("native_entry" if need_entry else None)
    checks: list = []
    if task is None:
        meta["llm"] = {**session.describe(), "status": "not_needed",
                       "detail": "deterministic analysis already mapped the changed code" if mapping.wrappers else
                       "nothing the model could add: no native code of the pinned version is linked to the fix"}
    else:
        identity = {"ecosystem": "PyPI", "package": dep.name, "package_version": dep.version, "advisory_id": adv.id,
                    "fix_commit": commit, "source_hash": index.source_hash(), "missing": sorted(missing)}
        request = _native_request(task, adv, dep, changes, mapping, index, missing, commit)
        result, llm_meta = session.ask(request, identity)
        if result is not None:
            for cand in result.candidates:
                if task == "pinned_equivalent":
                    target = cand.native_target if cand.native_target in missing else (missing[0] if len(missing) == 1 else None)
                    chk = verify.verify_native_equivalent(cand.symbol, target or "", index, changes["hunks"], [e.file for e in cand.evidence], sdist)
                    if chk.accepted and target:
                        mapping.equivalents.setdefault(target, []).append((cand.symbol, 0, 0.0))
                else:
                    chk = verify.verify_native_entry(cand, lib_src, sdist, index, mapping, dep.import_names)
                    if chk.accepted and chk.resolved:
                        mapping.entry_symbols.append(chk.resolved)
                        for q in chk.via:
                            mapping.wrappers.setdefault(q, []).extend(mapping.ambiguous.get(q, []))
                checks.append(chk)
            session.count(checks)
            record_verification(llm_meta.get("cache_key"), checks)
            if any(c.accepted for c in checks) and task == "pinned_equivalent":
                # re-run the mapping with the verified equivalents as targets
                extra = {e: {"file": index.get(e).file if index.get(e) else "", "lang": "c", "how": "llm_equivalent"}
                         for eqs in mapping.equivalents.values() for e, _h, _r in eqs if index.has(e)}
                remapped = native.map_to_python(index, {**changes, "functions": {**changes["functions"], **extra}}, lib_src, dep.import_names)
                remapped.equivalents.update(mapping.equivalents)
                remapped.gaps = [g for g in remapped.gaps if not (g.kind == "missing_in_pinned" and any(n in g.detail for n in mapping.equivalents))]
                mapping = remapped
            if any(c.accepted for c in checks):
                meta["method"] = "deterministic+llm"
        meta["llm"] = {**{k: v for k, v in llm_meta.items() if k != "cache_key"},
                       "candidates_suggested": len(checks), "candidates_verified": sum(c.accepted for c in checks),
                       "candidates_rejected": sum(not c.accepted for c in checks),
                       "candidates": [c.to_dict() for c in checks][:12],
                       "limitations": (result.limitations if result is not None else [])[:5]}
        meta["native"] = {**mapping.summary(), "source_files_indexed": index.files}
    meta["checks"] = {
        "source_verification": _check_label(bool(mapping.wrappers or mapping.entry_symbols), bool(mapping.closure)),
        "package_version_verification": "passed" if mapping.changed and all(v.get("pinned") or k in mapping.equivalents for k, v in mapping.changed.items())
        else ("failed" if mapping.changed else "not run"),
        "native_api_mapping": "verified" if mapping.complete else ("partial" if mapping.wrappers or mapping.entry_symbols else "unverified"),
    }
    return {"mapping": mapping, "metadata": meta, "commit": commit, "hunks": hunks}


def _numbered(text: str, start: int = 1) -> str:
    return "\n".join(f"{start + i}: {l}" for i, l in enumerate(text.splitlines()))


def _native_request(task: str, adv: Advisory, dep: Dependency, changes: dict, mapping, index, missing: list[str],
                    commit: Optional[str]) -> DiscoveryRequest:
    snippets: list[SourceSnippet] = []
    for h in changes["hunks"][:MAX_HUNKS_IN_PROMPT]:
        snippets.append(SourceSnippet(h["path"], 0, h["text"], "fix_diff"))
    allowed: list[str] = []
    targets: list[str] = []
    if task == "pinned_equivalent":
        files = {changes["functions"][m].get("file", "") for m in missing}
        allowed = sorted({f.name for funcs in index.functions.values() for f in funcs
                          if any(f.file.endswith(x) or x.endswith(f.file) for x in files)})[:200]
        if not allowed:
            lang = {changes["functions"][m].get("lang") for m in missing}
            allowed = sorted(n for n, fs in index.functions.items() if any(f.lang in lang for f in fs))[:200]
    else:
        targets = sorted(set(mapping.closure.hops) | {n for n, v in mapping.changed.items() if v.get("pinned")})[:30] if mapping.closure else []
        for r in mapping.registrations[:6]:
            snip = native.snippet(index, r.impl, max_lines=25)
            if snip:
                snippets.append(SourceSnippet(snip[0], snip[1], f"registered as Python name '{r.py_name}' ({r.kind})\n{snip[2]}", "registration"))
        for q, names in list(mapping.ambiguous.items())[:6]:
            snippets.append(SourceSnippet(q, 0, f"{q} calls .{', .'.join(sorted(set(names)))}() on an object of unknown type", "python_wrapper"))
    return DiscoveryRequest(
        task=task, ecosystem="PyPI", package=dep.name, package_version=dep.version, advisory_id=adv.id,
        summary=f"{adv.summary}\n{(adv.details or '')[:600]}", fix_commit=commit or "",
        changed_files=sorted({f["path"] for f in changes["files"]}), changed_functions=sorted(changes["functions"]),
        snippets=snippets, allowed_symbols=allowed, native_targets=targets)


# --- Python-tier version check --------------------------------------------------------------

def python_version_check(adv: Advisory, dep: Dependency, funcs: list[str], hunks: list[str], lib_src: Optional[Path],
                         session: Optional[LLMSession]) -> tuple[list[str], dict]:
    """Fix-commit functions missing from the pinned version -> verified pinned equivalents.

    Returns (extra qualnames to add as vulnerable functions, metadata)."""
    if lib_src is None or not funcs:
        return [], {}
    missing = [f for f in funcs if not verify.resolve_python_symbol(lib_src, f)]
    meta: dict = {"checked": len(funcs), "missing_in_pinned": missing[:10], "equivalents": {}}
    if not missing:
        return [], {"checked": len(funcs), "missing_in_pinned": []}
    extra: list[str] = []
    still: list[str] = []
    for m in missing:
        eqs = verify.python_equivalents(lib_src, m, hunks)
        if eqs:
            meta["equivalents"][m] = [{"name": q, "matching_lines": h, "ratio": r, "by": "code overlap"} for q, h, r in eqs]
            extra.extend(q for q, _h, _r in eqs)
        else:
            still.append(m)
    if still and session is not None and session.enabled:
        from .. import lib_graph
        model = lib_graph.load_model(lib_src)
        module = still[0].rsplit(".", 2)[0]
        allowed = sorted(q for q, i in model.functions.items() if not i.is_class and q.startswith(module + "."))[:200]
        req = DiscoveryRequest(task="pinned_equivalent", ecosystem="PyPI", package=dep.name, package_version=dep.version,
                               advisory_id=adv.id, summary=adv.summary, fix_commit="", changed_functions=still,
                               snippets=[SourceSnippet("fix", 0, h, "fix_diff") for h in hunks[:MAX_HUNKS_IN_PROMPT]],
                               allowed_symbols=allowed)
        identity = {"ecosystem": "PyPI", "package": dep.name, "package_version": dep.version, "advisory_id": adv.id,
                    "missing": still, "source_hash": hashlib.sha256("|".join(allowed).encode()).hexdigest()[:16]}
        result, llm_meta = session.ask(req, identity)
        checks = []
        for cand in (result.candidates if result is not None else []):
            chk = verify.verify_python_equivalent(cand.symbol, still[0], lib_src, hunks)
            checks.append(chk)
            if chk.accepted and chk.resolved:
                extra.append(chk.resolved)
                meta["equivalents"].setdefault(still[0], []).append({"name": chk.resolved, "by": "llm, verified by code overlap"})
        session.count(checks)
        record_verification(llm_meta.get("cache_key"), checks)
        meta["llm"] = {**{k: v for k, v in llm_meta.items() if k != "cache_key"}, "candidates": [c.to_dict() for c in checks][:8],
                       "candidates_suggested": len(checks), "candidates_verified": sum(c.accepted for c in checks),
                       "candidates_rejected": sum(not c.accepted for c in checks)}
    return sorted(set(extra)), meta


def short(text: str, n: int = 160) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= n else text[: n - 1] + "…"

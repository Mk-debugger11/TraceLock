"""LLM tier: propose public entry-API symbols; the caller verifies them against source. OWNER: Vaibhav.

"LLM proposes, AST verifies": the model only suggests names; kb.resolve() keeps a name only if
symbol_exists() finds it defined in the dependency's own source, so a hallucinated function can
never become a target. The LLM never decides a verdict.

Prompt = advisory summary + details + fix-commit hunks + the functions the fix touched + up to 400
public dotted names from the package source (_symbols_in). Answer format:
    {"entry_api": [...], "vulnerable_funcs": [...], "reasoning": "..."}
Providers (plain urllib, no SDK): ANTHROPIC_API_KEY (Messages API), else OPENAI_API_KEY (chat
completions), else a local Ollama at OLLAMA_HOST (default http://localhost:11434) when
TRACELOCK_LLM=ollama. Model names: TRACELOCK_LLM_MODEL (defaults below).

Cache: tracelock/data/llm_cache/<advisory_id>.json (committed) and .tracelock/cache/llm/ (local).
The cache is read first, so demos never wait on the network; it also records which proposals
passed verification against that exact package version, so --offline runs without the source
can reuse them (cached_verified).

    python -m tracelock.kb.llm --seed [CVE ...]            # needs a key: curated seed advisories
    python -m tracelock.kb.llm --seed --fixture ../benchmark/real_flask_app   # every advisory of a project
        Downloads the pinned wheels to .tracelock/cache/src (unzipped, never executed), writes
        data/llm_cache/<id>.json and copies the fix-commit analysis into data/fixes/.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Callable, Optional

from ..models import Advisory, Dependency, VulnSpec

DATA_CACHE = Path(__file__).resolve().parent.parent / "data" / "llm_cache"
LOCAL_CACHE = Path(".tracelock") / "cache" / "llm"
SRC_CACHE = Path(".tracelock") / "cache" / "src"
MAX_SYMBOLS = 400
MAX_DETAILS = 2500
MAX_HUNK_CHARS = 6000
DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5", "openai": "gpt-4o-mini", "ollama": "llama3.1"}
SYSTEM = ("You map security advisories for Python packages to the public API an application would call to "
          "reach the vulnerable code. Answer with one JSON object and nothing else.")

# Tests replace this with a fake: (system, prompt) -> (provider, model, response_text)
Transport = Callable[[str, str], tuple[str, str, str]]
_transport_override: Optional[Transport] = None


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


# --- prompt ---------------------------------------------------------------------------------

def public_symbols(lib_src: Path, dep: Dependency, spec: VulnSpec, cap: int = MAX_SYMBOLS) -> list[str]:
    """Public names under the dependency's import names, most relevant first, capped."""
    tops = set(dep.import_names)
    names = [s for s in _symbols_in(Path(lib_src))
             if s.split(".", 1)[0] in tops and not any(p.startswith("_") for p in s.split("."))]
    vuln_modules = {f.rsplit(".", 2)[0] for f in spec.vulnerable_funcs} | {f.rsplit(".", 1)[0] for f in spec.vulnerable_funcs}

    def rank(name: str) -> tuple:
        depth = name.count(".")
        near = any(name.startswith(m + ".") or name == m for m in vuln_modules)
        return (0 if depth <= 1 else 1 if near else 2, depth, name)

    return sorted(names, key=rank)[:cap]


def build_prompt(adv: Advisory, dep: Dependency, spec: VulnSpec, symbols: list[str]) -> str:
    hunks, used = [], 0
    for h in spec.evidence_hunks:
        if used + len(h) > MAX_HUNK_CHARS:
            break
        hunks.append(h)
        used += len(h)
    return "\n".join([
        f"Advisory {adv.id} (aliases: {', '.join(adv.aliases) or '-'}) for PyPI package {dep.name}=={dep.version}",
        f"import names: {', '.join(dep.import_names)}",
        f"summary: {adv.summary}",
        f"details: {adv.details[:MAX_DETAILS]}",
        "",
        "Functions changed by the fix commit (internal, dotted by import name):",
        *[f"- {f}" for f in spec.vulnerable_funcs],
        "",
        "Fix commit hunks:",
        *hunks,
        "",
        f"Public functions/classes defined in {dep.name}=={dep.version} (choose ONLY from this list):",
        ", ".join(symbols),
        "",
        "Which of the listed public names would application code call so that execution reaches the "
        "changed functions? Include module-level helpers and methods on public classes (Class.method). "
        "Do not invent names; a name not in the list will be discarded.",
        'Reply with JSON only: {"entry_api": [...], "vulnerable_funcs": [...], "reasoning": "one short paragraph"}',
    ])


# --- providers ------------------------------------------------------------------------------

def _post_json(url: str, body: dict, headers: dict, timeout: int = 90) -> dict:
    last: Exception = RuntimeError("no attempt")
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                         headers={"Content-Type": "application/json", **headers})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            last = exc
            if attempt < 2:
                time.sleep(1.0 * (2 ** attempt))
    raise last


def _call_llm(system: str, prompt: str) -> tuple[str, str, str]:
    if _transport_override is not None:
        return _transport_override(system, prompt)
    model = os.environ.get("TRACELOCK_LLM_MODEL")
    if os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("TRACELOCK_LLM", "anthropic") == "anthropic":
        model = model or DEFAULT_MODELS["anthropic"]
        data = _post_json("https://api.anthropic.com/v1/messages",
                          {"model": model, "max_tokens": 1500, "temperature": 0, "system": system,
                           "messages": [{"role": "user", "content": prompt}]},
                          {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"})
        text = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
        return "anthropic", model, text
    if os.environ.get("OPENAI_API_KEY") and os.environ.get("TRACELOCK_LLM", "openai") in ("openai", "anthropic"):
        model = model or DEFAULT_MODELS["openai"]
        data = _post_json("https://api.openai.com/v1/chat/completions",
                          {"model": model, "temperature": 0, "response_format": {"type": "json_object"},
                           "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]},
                          {"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"})
        return "openai", model, data["choices"][0]["message"]["content"]
    if os.environ.get("TRACELOCK_LLM") == "ollama":
        model = model or DEFAULT_MODELS["ollama"]
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        data = _post_json(f"{host}/api/chat", {"model": model, "stream": False, "format": "json",
                                               "messages": [{"role": "system", "content": system},
                                                            {"role": "user", "content": prompt}]}, {})
        return "ollama", model, data.get("message", {}).get("content", "")
    raise RuntimeError("no LLM configured (set ANTHROPIC_API_KEY or OPENAI_API_KEY, or TRACELOCK_LLM=ollama)")


def parse_response(text: str) -> dict:
    """First JSON object in the reply (tolerates ```json fences); lists keep only strings."""
    m = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not m:
        return {"entry_api": [], "vulnerable_funcs": [], "reasoning": ""}
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return {"entry_api": [], "vulnerable_funcs": [], "reasoning": ""}
    clean = lambda v: [x.strip() for x in v if isinstance(x, str) and x.strip()] if isinstance(v, list) else []
    return {"entry_api": clean(data.get("entry_api")), "vulnerable_funcs": clean(data.get("vulnerable_funcs")),
            "reasoning": str(data.get("reasoning", ""))[:2000]}


# --- cache ----------------------------------------------------------------------------------

def _cache_name(adv: Advisory) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", adv.id) + ".json"


def _read_cache(adv: Advisory, dep: Dependency) -> Optional[dict]:
    for base in (DATA_CACHE, LOCAL_CACHE):
        path = base / _cache_name(adv)
        if path.exists():
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if entry.get("package") == dep.name:
                return entry
    return None


def _write_cache(entry: dict, adv: Advisory, target: Optional[Path] = None) -> None:
    target = target if target is not None else LOCAL_CACHE  # resolved at call time
    try:
        target.mkdir(parents=True, exist_ok=True)
        (target / _cache_name(adv)).write_text(json.dumps(entry, indent=1) + "\n", encoding="utf-8")
    except OSError:
        pass


def cached_verified(adv: Advisory, dep: Dependency) -> list[str]:
    """Proposals that already passed symbol_exists against this exact package version (offline use)."""
    entry = _read_cache(adv, dep)
    if entry and entry.get("verified_version") == dep.version:
        return list(entry.get("verified", []))
    return []


def record_verified(adv: Advisory, dep: Dependency, verified: list[str]) -> None:
    """Remember which proposals passed verification for dep.version (local cache only)."""
    entry = _read_cache(adv, dep)
    if entry is None:
        return
    entry["verified"], entry["verified_version"] = verified, dep.version
    _write_cache(entry, adv)


def propose_entry_api(adv: Advisory, dep: Dependency, spec: VulnSpec, lib_src: Path, offline: bool = False) -> list[str]:
    """Ask an LLM which public symbols lead to spec.vulnerable_funcs (cache first). Unverified names."""
    entry = _read_cache(adv, dep)
    if entry is None:
        if offline:
            return []
        symbols = public_symbols(Path(lib_src), dep, spec)
        prompt = build_prompt(adv, dep, spec, symbols)
        provider, model, text = _call_llm(SYSTEM, prompt)
        entry = {"advisory_id": adv.id, "package": dep.name, "version": dep.version, "provider": provider,
                 "model": model, "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(), "symbols_offered": len(symbols),
                 "response_text": text, "parsed": parse_response(text)}
        _write_cache(entry, adv)
    return list(entry.get("parsed", {}).get("entry_api", []))


# --- seeding (needs a key) --------------------------------------------------------------------

def _fetch_wheel_source(name: str, version: str) -> Optional[Path]:
    """Unpack the pure/any wheel (else the first wheel) of name==version into .tracelock/cache/src. Never executes it."""
    dest = SRC_CACHE / f"{name}-{version}"
    if dest.exists():
        return dest
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as resp:
        files = json.loads(resp.read().decode("utf-8"))["urls"]
    wheels = [f for f in files if f["filename"].endswith(".whl")]
    if not wheels:
        return None
    wheels.sort(key=lambda f: (0 if "none-any" in f["filename"] else 1, f["filename"]))
    with urllib.request.urlopen(wheels[0]["url"], timeout=120) as resp:
        blob = resp.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for member in zf.namelist():
            if member.startswith("/") or ".." in Path(member).parts:
                raise RuntimeError(f"unsafe path in wheel: {member}")
        zf.extractall(dest)
    return dest


def _seed_one(adv: Advisory, dep: Dependency, curated_entry: Optional[list] = None) -> tuple[list[str], bool]:
    """Propose + verify one advisory against the real wheel; persist LLM and fix-commit results under data/."""
    from . import fixdiff  # noqa: PLC0415
    lib_src = _fetch_wheel_source(dep.name, dep.version)
    if lib_src is None:
        print(f"{adv.id} {dep.name}=={dep.version}: no wheel on PyPI, skipped", file=sys.stderr)
        return [], False
    funcs, hunks, commit = fixdiff.functions_from_fix(adv, dep)
    if not funcs:
        print(f"{adv.id} {dep.name}=={dep.version}: fix commit names no function, skipped", file=sys.stderr)
        return [], False
    fixdiff.persist(adv)  # copy the fix-commit analysis into data/fixes so --offline sees the functions
    spec = VulnSpec(advisory_id=adv.id, package=dep.name, vulnerable_funcs=funcs, evidence_hunks=hunks, fix_commit=commit)
    proposed = propose_entry_api(adv, dep, spec, lib_src)
    verified = [n for n in proposed if symbol_exists(lib_src, dep, n)]
    entry = _read_cache(adv, dep) or {}
    entry.update({"verified": verified, "verified_version": dep.version, "rejected": [n for n in proposed if n not in verified]})
    _write_cache(entry, adv, DATA_CACHE)
    overlap = bool(set(curated_entry or []) & set(verified))
    print(f"{adv.id} {dep.name}=={dep.version}: verified {verified} rejected {entry['rejected']}"
          + (f"  [overlaps curated: {overlap}]" if curated_entry else ""), file=sys.stderr)
    return verified, overlap


def _seed(args: list[str]) -> int:
    """--seed [CVE ...]: curated advisories at their seed pins. --seed --fixture DIR: every advisory of a project."""
    from .. import deps as deps_mod, osv  # noqa: PLC0415
    from . import _curated  # noqa: PLC0415
    if args[:1] == ["--fixture"]:
        root = Path(args[1])
        dependencies = deps_mod.scan_dependencies(root)
        found = osv.lookup(dependencies, offline=True)
        done = 0
        for dep in dependencies:
            for adv in found.get(dep.name, []):
                done += bool(_seed_one(adv, dep)[0])
        print(f"{done} advisories in {root} now have verified entry points cached", file=sys.stderr)
        return 0
    curated = _curated()
    snapshot = osv._load_snapshot()
    pins = {"pyyaml": "5.3", "jinja2": "3.1.2", "requests": "2.30.0", "urllib3": "2.0.6", "pillow": "10.1.0",
            "werkzeug": "2.2.2", "flask": "2.2.4", "setuptools": "69.0.3", "pyjwt": "2.3.0", "python-multipart": "0.0.6",
            "aiohttp": "3.9.1", "black": "23.12.1", "cryptography": "41.0.5", "tqdm": "4.66.1", "certifi": "2022.9.24"}
    targets = args or [k for k in curated if not k.startswith("_")]
    agree = tried = 0
    for cve in targets:
        package = curated.get(cve, {}).get("package") or next(
            (p for p, recs in snapshot.items() if any(cve in r.get("aliases", []) for r in recs)), None)
        if not package:
            print(f"{cve}: not in snapshot", file=sys.stderr)
            continue
        adv = osv.merge_aliases([r for r in snapshot[package] if cve in r.get("aliases", []) or r["id"] == cve], package)[0]
        dep = Dependency(package, pins.get(package, "0"), import_names=deps_mod.import_names_for(package))
        verified, overlap = _seed_one(adv, dep, curated.get(cve, {}).get("entry_api"))
        tried += bool(verified)
        agree += overlap
    print(f"{agree}/{tried} verified LLM proposals overlap the hand-curated entry_api", file=sys.stderr)
    return 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["--seed"]:
        try:
            sys.exit(_seed(sys.argv[2:]))
        except RuntimeError as exc:  # no key / provider configured
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)
    print(__doc__)
    sys.exit(2)

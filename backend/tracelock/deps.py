"""Dependency discovery. OWNER: Vaibhav.

Sources, highest precedence first (a package found in a higher source keeps that version):
  1. lock files: poetry.lock, uv.lock (TOML: tomllib on 3.11+, else tomli), Pipfile.lock (JSON)
  2. a virtualenv inside the project: .venv|venv|env/lib/python*/site-packages/*.dist-info/METADATA
  3. requirements*.txt  (`name==version` only)
  4. pyproject.toml     ([project].dependencies and [tool.poetry.dependencies], exact pins only)

Unpinned specs (`requests>=2`, `flask = "^2.2"`, URL requirements) cannot be matched against OSV
ranges, so they are skipped and described in the module-level WARNINGS list, which
scan_dependencies() refills on every call; tracelock.scan() copies it into ScanResult.warnings.

Dependency.requires (used by the verdict engine's transitive rule) comes from the lock file's
dependency graph or the venv's Requires-Dist; otherwise from data/pypi_requires.json (PyPI
metadata for the seed pins). pypi_source.fetch() may refine import_names/requires later.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from .models import Dependency

WARNINGS: list[str] = []
REQUIRES_DATA = Path(__file__).parent / "data" / "pypi_requires.json"
SKIP_DIRS = {".venv", "venv", "env", "node_modules", ".git", ".tox", ".nox", ".tracelock", "__pycache__", "site-packages"}
VENV_DIRS = (".venv", "venv", "env")
LOCK_FILES = ("poetry.lock", "uv.lock", "Pipfile.lock")

# distribution name -> top-level import names, for the cases that are not name.replace('-', '_')
IMPORT_NAME_MAP = {
    "pyyaml": ["yaml"],
    "pillow": ["PIL"],
    "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"],
    "python-multipart": ["multipart", "python_multipart"],
    "pyjwt": ["jwt"],
    "opencv-python": ["cv2"],
    "python-dateutil": ["dateutil"],
    "msgpack-python": ["msgpack"],
    "attrs": ["attr", "attrs"],
    "pycryptodome": ["Crypto"],
    "protobuf": ["google"],
    "python-dotenv": ["dotenv"],
    "typing-extensions": ["typing_extensions"],
    "markupsafe": ["markupsafe"],
    "jinja2": ["jinja2"],
    "flask": ["flask"],
    "werkzeug": ["werkzeug"],
    "requests": ["requests"],
    "urllib3": ["urllib3"],
    "cryptography": ["cryptography"],
    "setuptools": ["setuptools", "pkg_resources", "_distutils_hack"],
    "aiohttp": ["aiohttp"],
    "black": ["black", "blackd", "blib2to3"],
    "certifi": ["certifi"],
    "tqdm": ["tqdm"],
}

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_EXACT_RE = re.compile(r"^==\s*([A-Za-z0-9.!+-]+)\s*$")
_requires_cache: Optional[dict] = None


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def import_names_for(name: str) -> list[str]:
    name = normalize_name(name)
    return list(IMPORT_NAME_MAP.get(name, [name.replace("-", "_")]))


def _dep(name: str, version: str, source: str, requires: Optional[list[str]] = None,
         import_names: Optional[list[str]] = None) -> Dependency:
    name = normalize_name(name)
    return Dependency(name=name, version=str(version).strip(), import_names=import_names or import_names_for(name),
                      requires=sorted({normalize_name(r) for r in requires or []}), source=source)


def _exact_version(spec: str) -> Optional[str]:
    """'==1.2.3' -> '1.2.3'; anything else (ranges, wildcards, multiple clauses) -> None."""
    m = _EXACT_RE.match(spec.strip())
    if not m or "*" in m.group(1):
        return None
    return m.group(1)


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _toml(path: Path, root: Path) -> Optional[dict]:
    try:
        import tomllib  # py311+
    except ImportError:  # pragma: no cover
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            WARNINGS.append(f"{_rel(path, root)}: found but cannot be read without Python 3.11+ or the 'tomli' package; skipped")
            return None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        WARNINGS.append(f"{_rel(path, root)}: could not parse ({exc}); skipped")
        return None


def _walk(root: Path, pattern: str):
    for path in sorted(root.rglob(pattern)):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.is_file():
            yield path


# --- lock files ------------------------------------------------------------------------------

def _parse_poetry_lock(path: Path, root: Path) -> list[Dependency]:
    data = _toml(path, root)
    if data is None:
        return []
    deps = []
    for pkg in data.get("package", []) or []:
        if pkg.get("name") and pkg.get("version"):
            deps.append(_dep(pkg["name"], pkg["version"], "lock", requires=list((pkg.get("dependencies") or {}).keys())))
    return deps


def _parse_uv_lock(path: Path, root: Path) -> list[Dependency]:
    data = _toml(path, root)
    if data is None:
        return []
    deps = []
    for pkg in data.get("package", []) or []:
        source = pkg.get("source") or {}
        if not pkg.get("name") or not pkg.get("version") or "editable" in source or "virtual" in source:
            continue  # the project itself, or a path dependency without a release version
        requires = [d.get("name", "") for d in pkg.get("dependencies", []) or [] if isinstance(d, dict)]
        deps.append(_dep(pkg["name"], pkg["version"], "lock", requires=[r for r in requires if r]))
    return deps


def _parse_pipfile_lock(path: Path, root: Path, unpinned: dict) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        WARNINGS.append(f"{_rel(path, root)}: could not parse ({exc}); skipped")
        return []
    deps = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = _exact_version((info or {}).get("version", "")) if isinstance(info, dict) else None
            if version:
                deps.append(_dep(name, version, "lock"))
            else:
                unpinned.setdefault(normalize_name(name), f"{_rel(path, root)}: '{name}' has no exact version (VCS/path entry)")
    return deps


# --- virtualenv ------------------------------------------------------------------------------

def _read_metadata(meta: Path) -> tuple[Optional[str], Optional[str], list[str]]:
    name = version = None
    requires: list[str] = []
    for line in meta.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            break  # end of the RFC 822 header block; the long description follows
        key, _, value = line.partition(":")
        value = value.strip()
        if key == "Name":
            name = value
        elif key == "Version":
            version = value
        elif key == "Requires-Dist":
            marker = value.split(";", 1)[1] if ";" in value else ""
            if re.search(r"\bextra\s*==", marker):
                continue
            m = _REQ_RE.match(value)
            if m:
                requires.append(m.group(1))
    return name, version, requires


def _parse_venv(root: Path) -> list[Dependency]:
    deps = []
    for vdir in VENV_DIRS:
        base = root / vdir
        if not base.is_dir():
            continue
        metas = sorted([*base.glob("lib/python*/site-packages/*.dist-info/METADATA"),
                        *base.glob("Lib/site-packages/*.dist-info/METADATA")])
        for meta in metas:
            try:
                name, version, requires = _read_metadata(meta)
            except OSError:
                continue
            if not name or not version:
                continue
            imports = None
            top = meta.parent / "top_level.txt"
            if top.exists():
                names = [n.strip() for n in top.read_text(encoding="utf-8", errors="replace").splitlines() if n.strip()]
                public = [n for n in names if not n.startswith("_")]
                imports = public or names or None
            deps.append(_dep(name, version, "venv", requires=requires, import_names=imports))
    return deps


# --- requirements / pyproject ----------------------------------------------------------------

def _parse_requirements(path: Path, root: Path, unpinned: dict) -> list[Dependency]:
    deps = []
    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw_line.split(" #", 1)[0].split("\t#", 1)[0]
        line = line[:-1] if line.rstrip().endswith("\\") else line
        line = line.split(";", 1)[0].strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue  # comments, options (-r, -c, -e, --hash, --index-url)
        where = f"{_rel(path, root)}:{lineno}"
        if "://" in line or line.startswith(("git+", "hg+", "svn+", "bzr+")):
            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*@", line)
            key = normalize_name(m.group(1)) if m else line
            unpinned.setdefault(key, f"{where}: '{line}' is a URL/VCS requirement, not an exact version")
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        version = _exact_version(m.group(3))
        if version:
            deps.append(_dep(m.group(1), version, "requirements"))
        else:
            unpinned.setdefault(normalize_name(m.group(1)), f"{where}: '{line}' is not pinned to an exact version (==)")
    return deps


def _parse_pyproject(path: Path, root: Path, unpinned: dict) -> list[Dependency]:
    data = _toml(path, root)
    if data is None:
        return []
    deps = []
    where = _rel(path, root)
    for spec in data.get("project", {}).get("dependencies", []) or []:
        spec = spec.split(";", 1)[0].strip()
        m = _REQ_RE.match(spec)
        if not m:
            continue
        version = _exact_version(m.group(3))
        if version:
            deps.append(_dep(m.group(1), version, "pyproject"))
        else:
            unpinned.setdefault(normalize_name(m.group(1)), f"{where}: '{spec}' is not pinned to an exact version (==)")
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        raw = spec.get("version", "") if isinstance(spec, dict) else spec
        raw = str(raw or "").strip()
        version = raw[2:].strip() if raw.startswith("==") else raw if re.fullmatch(r"\d[A-Za-z0-9.!+-]*", raw) else None
        if version:
            deps.append(_dep(name, version, "pyproject"))
        else:
            unpinned.setdefault(normalize_name(name), f"{where}: '{name} = {raw or spec}' is not pinned to an exact version")
    return deps


# --- requires fallback -----------------------------------------------------------------------

def _requires_table() -> dict:
    global _requires_cache
    if _requires_cache is None:
        try:
            raw = json.loads(REQUIRES_DATA.read_text(encoding="utf-8"))
            _requires_cache = {normalize_name(k): v for k, v in raw.items() if not k.startswith("_")}
        except (OSError, ValueError):
            _requires_cache = {}
    return _requires_cache


def _known_requires(dep: Dependency) -> list[str]:
    """Requires for dep from PyPI metadata snapshot: exact version, else the newest recorded version."""
    versions = _requires_table().get(dep.name) or {}
    if dep.version in versions:
        return list(versions[dep.version])
    if not versions:
        return []
    from .osv import _version_key  # local import: osv imports nothing from deps
    newest = max(versions, key=_version_key)
    return list(versions[newest])


# --- entry point -----------------------------------------------------------------------------

def scan_dependencies(root: Path) -> list[Dependency]:
    """Pinned dependencies under `root`, deduplicated by name with lock > venv > requirements > pyproject.

    Refills the module-level WARNINGS list (unpinned specs, unreadable files)."""
    root = Path(root)
    WARNINGS.clear()
    unpinned: dict[str, str] = {}
    layers: list[list[Dependency]] = []

    locks: list[Dependency] = []
    for lock_name in LOCK_FILES:
        for path in _manifests(root, lock_name):
            if lock_name == "poetry.lock":
                locks.extend(_parse_poetry_lock(path, root))
            elif lock_name == "uv.lock":
                locks.extend(_parse_uv_lock(path, root))
            else:
                locks.extend(_parse_pipfile_lock(path, root, unpinned))
    layers.append(locks)
    layers.append(_parse_venv(root))
    reqs: list[Dependency] = []
    for path in _manifests(root, "requirements*.txt"):
        reqs.extend(_parse_requirements(path, root, unpinned))
    layers.append(reqs)
    pyproject = root / "pyproject.toml"
    layers.append(_parse_pyproject(pyproject, root, unpinned) if pyproject.exists() else [])

    found: dict[str, Dependency] = {}
    for layer in layers:
        for dep in layer:
            found.setdefault(dep.name, dep)

    for dep in found.values():
        if not dep.requires:
            dep.requires = _known_requires(dep)
    for name, message in unpinned.items():
        if name not in found:
            # Keep the package with an unknown version: every advisory for it is reported, and the
            # verdict engine marks those UNCERTAIN (or NOT_REACHABLE when it is never imported).
            found[name] = Dependency(name=name, version="", import_names=import_names_for(name), source="unpinned")
            WARNINGS.append(message + "; version unknown, so all of its advisories are checked and reported as uncertain")
    return list(found.values())


def _manifests(root: Path, pattern: str):
    """Manifests to read. Root-level ones win: a monorepo's nested requirements (sub-projects,
    fixtures, examples) are ignored when the root has its own, and named in WARNINGS."""
    paths = list(_walk(root, pattern))
    top = [p for p in paths if p.parent == root]
    if top and len(paths) > len(top):
        nested = [str(p.relative_to(root)) for p in paths if p.parent != root]
        WARNINGS.append(f"{pattern}: using the root manifest(s) only; nested ones ignored: {', '.join(nested[:6])}"
                        + (" ..." if len(nested) > 6 else ""))
        return top
    return paths

"""Dependency discovery. OWNER: Vaibhav.

Scaffold status: parses pinned `name==version` lines from requirements*.txt and
`[project].dependencies` from pyproject.toml. TODO (Vaibhav): poetry/uv/Pipfile
locks, a venv inside the project (importlib.metadata), extras, markers,
better import-name mapping (pypi_source.fetch refines it from top_level.txt).
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import Dependency

# distribution name -> top-level import names, for the cases that are not name.replace('-', '_')
IMPORT_NAME_MAP = {
    "pyyaml": ["yaml"],
    "pillow": ["PIL"],
    "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"],
    "python-multipart": ["multipart"],
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
    "setuptools": ["setuptools", "pkg_resources"],
    "aiohttp": ["aiohttp"],
    "black": ["black"],
    "certifi": ["certifi"],
    "tqdm": ["tqdm"],
}

_PIN_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+*-]+)")


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def import_names_for(name: str) -> list[str]:
    name = normalize_name(name)
    return IMPORT_NAME_MAP.get(name, [name.replace("-", "_")])


def _parse_requirements(path: Path) -> list[Dependency]:
    deps = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _PIN_RE.match(line)
        if not m:
            continue  # unpinned or complex specifier: TODO report as warning
        name = normalize_name(m.group(1))
        deps.append(Dependency(name=name, version=m.group(3), import_names=import_names_for(name), source="requirements"))
    return deps


def _parse_pyproject(path: Path) -> list[Dependency]:
    try:
        import tomllib  # py311+
    except ImportError:  # pragma: no cover
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    specs = list(data.get("project", {}).get("dependencies", []) or [])
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, str) and spec and spec[0].isdigit():
            specs.append(f"{name}=={spec}")
        elif isinstance(spec, dict) and str(spec.get("version", ""))[:1].isdigit():
            specs.append(f"{name}=={spec['version']}")
    deps = []
    for spec in specs:
        m = _PIN_RE.match(spec)
        if m:
            name = normalize_name(m.group(1))
            deps.append(Dependency(name=name, version=m.group(3), import_names=import_names_for(name), source="pyproject"))
    return deps


def scan_dependencies(root: Path) -> list[Dependency]:
    """Return pinned dependencies found under `root` (requirements*.txt, pyproject.toml). Deduplicated by name."""
    found: dict[str, Dependency] = {}
    for path in sorted(root.rglob("requirements*.txt")):
        if any(part in {".venv", "venv", "node_modules", ".git"} for part in path.parts):
            continue
        for dep in _parse_requirements(path):
            found.setdefault(dep.name, dep)
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        for dep in _parse_pyproject(pyproject):
            found.setdefault(dep.name, dep)
    return list(found.values())

"""Fetch a dependency's source from PyPI WITHOUT installing or executing it. OWNER: Mukul.

 1. Look in tracelock/data/wheels/ (pre-downloaded seed archives) and in
    .tracelock/cache/src/<name>-<version>/ (already unpacked).
 2. Else download: `pip download <name>==<version> --no-deps --only-binary :all:` (a wheel; pip never
    builds or runs anything for --only-binary). If that fails, pick a file from the PyPI JSON API
    (pure wheel > CPython 3 wheel for any platform > sdist) and check its sha256. We do NOT use
    `pip download --no-binary`, because pip runs an sdist's setup.py to read its metadata.
 3. Extract a wheel (zip) or sdist (tar.gz / zip) into .tracelock/cache/src/<name>-<version>/,
    rejecting absolute and '..' members, never creating links, with size and member caps.
    An sdist's package directory (src/, lib3/, lib/ or the top level) is moved up and given a
    synthesized <dist>.dist-info, so every cache entry has the same layout as an unpacked wheel.
 4. Return the directory that contains the top-level package(s): `yaml/__init__.py` lives in it.
 5. Refine dep.import_names from <dist>.dist-info/top_level.txt (or RECORD, or package dirs) and
    fill dep.requires from METADATA 'Requires-Dist:' (name only; entries behind an `extra ==`
    marker are dropped so optional deps do not create transitive edges). Mutates dep in place.
"""
from __future__ import annotations

import csv
import email.parser
import hashlib
import json
import logging
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Optional

from .models import Dependency

logger = logging.getLogger(__name__)

DATA_WHEELS = Path(__file__).parent / "data" / "wheels"
CACHE_SRC = Path(".tracelock") / "cache" / "src"
CACHE_DL = Path(".tracelock") / "cache" / "dl"
PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"

PIP_TIMEOUT = 60
HTTP_TIMEOUT = 60
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
MAX_EXTRACT_BYTES = 300 * 1024 * 1024
MAX_MEMBERS = 50_000

# Requirement names come from the scanned project, so they are validated before reaching pip or a URL.
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}")
_SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_-]{0,100}")
_REQ_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_EXTRA_MARKER = re.compile(r"\bextra\s*==")
_NOT_PACKAGES = {"test", "tests", "testing", "docs", "doc", "examples", "benchmarks", "scripts"}


class ArchiveError(Exception):
    """A download or archive we refuse to use."""


def fetch(dep: Dependency, offline: bool = False) -> Optional[Path]:
    """Return the unpacked source root for dep, or None if unavailable. Never raises for a bad package."""
    if not (_SAFE_NAME.fullmatch(dep.name) and _SAFE_VERSION.fullmatch(dep.version)):
        logger.warning("refusing to fetch suspicious requirement %r==%r", dep.name, dep.version)
        return None
    target = CACHE_SRC / f"{dep.name}-{dep.version}"
    if not target.is_dir():
        try:
            archive = _seed_archive(dep) or (None if offline else _download(dep))
            if archive is None:
                return None
            _unpack(archive, dep, target)
        except (ArchiveError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
            logger.warning("could not get source for %s==%s: %s", dep.name, dep.version, exc)
            return None
    _read_metadata(dep, target)
    return target.resolve()


CACHE_NATIVE = Path(".tracelock") / "cache" / "native-src"
# What native-extension analysis reads from an sdist; everything else (test images, docs) is skipped.
NATIVE_KEEP = (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".rs", ".py", ".pyx", ".pxd", ".pyi", ".toml")


def fetch_sdist(dep: Dependency, offline: bool = False) -> Optional[Path]:
    """The unpacked sdist of dep==version, source files only, for C / Rust extension analysis.

    Wheels ship compiled .so/.pyd files, so the pinned version's native source only exists in the
    sdist. It is downloaded from PyPI with its sha256 checked, unpacked with the same path/size
    checks as fetch(), and never built, imported or executed. None when offline or unavailable."""
    if not (_SAFE_NAME.fullmatch(dep.name) and _SAFE_VERSION.fullmatch(dep.version)):
        return None
    target = CACHE_NATIVE / f"{dep.name}-{dep.version}"
    if not target.is_dir():
        if offline:
            return None
        try:
            archive = _pypi_sdist(dep)
            if archive is None:
                return None
            CACHE_NATIVE.mkdir(parents=True, exist_ok=True)
            work = Path(tempfile.mkdtemp(prefix=f".tmp-{dep.name}-", dir=CACHE_NATIVE))
            try:
                staged = work / "staged"
                (_extract_zip if archive.name.endswith(".zip") else _extract_tar)(archive, staged, keep=NATIVE_KEEP)
                try:
                    staged.rename(target)
                except OSError:
                    if not target.is_dir():
                        raise
            finally:
                shutil.rmtree(work, ignore_errors=True)
                archive.unlink(missing_ok=True)
        except (ArchiveError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
            logger.warning("could not get sdist for %s==%s: %s", dep.name, dep.version, exc)
            return None
    entries = [p for p in target.iterdir()]
    return (entries[0] if len(entries) == 1 and entries[0].is_dir() else target).resolve()


def _pypi_sdist(dep: Dependency) -> Optional[Path]:
    try:
        with urllib.request.urlopen(PYPI_JSON.format(name=dep.name, version=dep.version), timeout=HTTP_TIMEOUT) as resp:
            files = json.load(resp).get("urls", [])
    except (OSError, ValueError):
        return None
    sdists = [f for f in files if f.get("packagetype") == "sdist" and f.get("filename", "").endswith((".tar.gz", ".zip"))]
    if not sdists:
        return None
    entry = sdists[0]
    dest = CACHE_DL / f"{dep.name}-{dep.version}-sdist"
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    path = dest / PurePosixPath(entry["filename"]).name
    _http_download(entry["url"], path, entry.get("digests", {}).get("sha256"))
    return path


def canonical(name: str) -> str:
    """PEP 503 normalised name, matching Dependency.name."""
    return re.sub(r"[-_.]+", "-", name).lower()


# --- finding an archive --------------------------------------------------------


def _archive_id(filename: str) -> Optional[tuple[str, str]]:
    """(canonical name, version) from a wheel or sdist file name."""
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        return (canonical(parts[0]), parts[1]) if len(parts) >= 5 else None
    for ext in (".tar.gz", ".tgz", ".zip"):
        if filename.endswith(ext):
            name, _, version = filename[: -len(ext)].rpartition("-")
            return (canonical(name), version) if name else None
    return None


def _seed_archive(dep: Dependency) -> Optional[Path]:
    if not DATA_WHEELS.is_dir():
        return None
    matches = [p for p in DATA_WHEELS.iterdir() if _archive_id(p.name) == (dep.name, dep.version)]
    return min(matches, key=lambda p: (not p.name.endswith(".whl"), p.name)) if matches else None


def _download(dep: Dependency) -> Optional[Path]:
    dest = CACHE_DL / f"{dep.name}-{dep.version}"
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    return _pip_wheel(dep, dest) or _pypi_file(dep, dest)


def _pip_wheel(dep: Dependency, dest: Path) -> Optional[Path]:
    cmd = [
        sys.executable, "-m", "pip", "download", f"{dep.name}=={dep.version}",
        "--no-deps", "--only-binary", ":all:", "--disable-pip-version-check", "--no-input", "--quiet",
        "-d", str(dest),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=PIP_TIMEOUT, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    wheels = sorted(dest.glob("*.whl"))
    return wheels[0] if proc.returncode == 0 and wheels else None


def _file_rank(entry: dict) -> Optional[tuple]:
    """Sort key for a PyPI release file, lower is better; None for files we never use (py2-only wheels)."""
    filename = entry.get("filename", "")
    if entry.get("packagetype") == "bdist_wheel" and filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) < 5:
            return None
        tags, platform = parts[-3].split("."), parts[-1]
        if platform == "any" and any(t.startswith("py3") for t in tags):
            return (0, 0, entry.get("size", 0))
        cpython3 = [int(t[3:]) for t in tags if re.fullmatch(r"cp3\d+", t)]
        if cpython3:  # the .py files are the same on every platform; we never load the binaries
            return (1, -max(cpython3), entry.get("size", 0))
        return None
    if entry.get("packagetype") == "sdist" and filename.endswith((".tar.gz", ".zip")):
        return (2, 0, entry.get("size", 0))
    return None


def _pypi_file(dep: Dependency, dest: Path) -> Optional[Path]:
    try:
        with urllib.request.urlopen(PYPI_JSON.format(name=dep.name, version=dep.version), timeout=HTTP_TIMEOUT) as resp:
            files = json.load(resp).get("urls", [])
    except (OSError, ValueError):
        return None
    ranked = [(rank, f) for f in files if (rank := _file_rank(f)) is not None]
    if not ranked:
        return None
    entry = min(ranked, key=lambda pair: pair[0])[1]
    path = dest / PurePosixPath(entry["filename"]).name
    _http_download(entry["url"], path, entry.get("digests", {}).get("sha256"))
    return path


def _http_download(url: str, path: Path, sha256: Optional[str]) -> None:
    if not url.startswith("https://"):
        raise ArchiveError(f"refusing non-https download {url}")
    digest, total = hashlib.sha256(), 0
    with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as resp, open(path, "wb") as out:
        while chunk := resp.read(1 << 20):
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise ArchiveError("download is too large")
            digest.update(chunk)
            out.write(chunk)
    if sha256 and digest.hexdigest() != sha256:
        path.unlink(missing_ok=True)
        raise ArchiveError("sha256 mismatch")


# --- unpacking -----------------------------------------------------------------


def _unpack(archive: Path, dep: Dependency, target: Path) -> None:
    CACHE_SRC.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f".tmp-{dep.name}-", dir=CACHE_SRC))
    try:
        staged = work / "staged"
        if archive.name.endswith(".whl"):
            _extract_zip(archive, staged)
        else:
            raw = work / "raw"
            (_extract_zip if archive.name.endswith(".zip") else _extract_tar)(archive, raw)
            _stage_sdist(raw, dep, staged)
        try:
            staged.rename(target)  # atomic, so a half-unpacked tree is never mistaken for a cache hit
        except OSError:
            if not target.is_dir():
                raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _safe_relpath(name: str) -> Optional[PurePosixPath]:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
        raise ArchiveError(f"unsafe archive member {name[:200]!r}")
    parts = [p for p in path.parts if p != "."]
    return PurePosixPath(*parts) if parts else None


def _copy_capped(src: BinaryIO, out: BinaryIO, total: int) -> int:
    while chunk := src.read(1 << 20):
        total += len(chunk)
        if total > MAX_EXTRACT_BYTES:
            raise ArchiveError("archive expands beyond the size cap")
        out.write(chunk)
    return total


def _extract_zip(archive: Path, dest: Path, keep: Optional[tuple] = None) -> None:
    dest.mkdir(parents=True)
    total = 0
    with zipfile.ZipFile(archive) as zf:
        members = zf.infolist()
        if len(members) > MAX_MEMBERS:
            raise ArchiveError("archive has too many members")
        for member in members:
            relative = _safe_relpath(member.filename)
            if relative is None or stat.S_ISLNK(member.external_attr >> 16):
                continue
            if keep and not member.is_dir() and not relative.name.endswith(keep):
                continue
            out = dest.joinpath(*relative.parts)
            if member.is_dir():
                out.mkdir(parents=True, exist_ok=True)
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, open(out, "wb") as fh:
                total = _copy_capped(src, fh, total)


def _extract_tar(archive: Path, dest: Path, keep: Optional[tuple] = None) -> None:
    dest.mkdir(parents=True)
    total = count = 0
    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            count += 1
            if count > MAX_MEMBERS:
                raise ArchiveError("archive has too many members")
            relative = _safe_relpath(member.name)
            if relative is None:
                continue
            out = dest.joinpath(*relative.parts)
            if member.isdir():
                out.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():  # symlinks, hard links, devices and fifos are never created
                continue
            if keep and not relative.name.endswith(keep):
                continue
            src = tf.extractfile(member)
            if src is None:
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            with src, open(out, "wb") as fh:
                total = _copy_capped(src, fh, total)


def _stage_sdist(raw: Path, dep: Dependency, staged: Path) -> None:
    """Move an sdist's top-level packages into `staged` and write a minimal dist-info beside them."""
    entries = list(raw.iterdir())
    top = entries[0] if len(entries) == 1 and entries[0].is_dir() else raw
    egg_info = next((p for pattern in ("*.egg-info", "src/*.egg-info", "lib*/*.egg-info") for p in sorted(top.glob(pattern))), None)
    declared = _lines(egg_info / "top_level.txt") if egg_info else []
    wanted = declared or dep.import_names

    roots = [top / sub for sub in ("src", "lib3", "lib") if (top / sub).is_dir()] + [top]
    root = next((r for r in roots if any(_is_module(r, n) for n in wanted)), None)
    if root is None:  # no declared name matched: take the first root that has any package at all
        root = next((r for r in roots if _package_dirs(r)), top)
    names = [n for n in wanted if _is_module(root, n)] or _package_dirs(root)

    staged.mkdir(parents=True)
    for name in names:
        for candidate in (root / name, root / f"{name}.py"):
            if candidate.exists():
                shutil.move(str(candidate), str(staged / candidate.name))

    info = staged / f"{dep.name.replace('-', '_')}-{dep.version}.dist-info"
    info.mkdir()
    (info / "top_level.txt").write_text("".join(f"{n}\n" for n in names), encoding="utf-8")
    requires = _pkg_info_requires(top / "PKG-INFO") or _egg_requires(egg_info)
    metadata = ["Metadata-Version: 2.1", f"Name: {dep.name}", f"Version: {dep.version}"]
    metadata += [f"Requires-Dist: {r}" for r in requires]
    (info / "METADATA").write_text("\n".join(metadata) + "\n", encoding="utf-8")


def _is_module(root: Path, name: str) -> bool:
    return (root / name / "__init__.py").is_file() or (root / f"{name}.py").is_file()


def _package_dirs(root: Path) -> list[str]:
    return sorted(p.name for p in root.iterdir() if (p / "__init__.py").is_file() and p.name not in _NOT_PACKAGES)


def _lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def _pkg_info_requires(path: Path) -> list[str]:
    if not path.is_file():
        return []
    msg = email.parser.HeaderParser().parsestr(path.read_text(encoding="utf-8", errors="replace"))
    return list(msg.get_all("Requires-Dist") or [])


def _egg_requires(egg_info: Optional[Path]) -> list[str]:
    """requires.txt lines outside extra sections; '[:marker]' sections keep their marker."""
    if egg_info is None:
        return []
    out, marker, in_extra = [], "", False
    for line in _lines(egg_info / "requires.txt"):
        if line.startswith("["):
            extra, _, marker = line.strip("[]").partition(":")
            in_extra = bool(extra)
            continue
        if not in_extra:
            out.append(f"{line}; {marker}" if marker else line)
    return out


# --- metadata ------------------------------------------------------------------


def _dist_info(root: Path, dep: Dependency) -> Optional[Path]:
    infos = sorted(root.glob("*.dist-info"))
    for info in infos:
        if canonical(info.name[: -len(".dist-info")].rpartition("-")[0]) == dep.name:
            return info
    return infos[0] if infos else None


def _top_level(info: Path) -> list[str]:
    names = _lines(info / "top_level.txt")
    if not names and (info / "RECORD").is_file():
        with open(info / "RECORD", newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if not row:
                    continue
                parts = row[0].split("/")
                if len(parts) > 1:
                    if not parts[0].endswith((".dist-info", ".data")):
                        names.append(parts[0])
                elif parts[0].endswith((".py", ".so", ".pyd")):
                    names.append(parts[0].split(".", 1)[0])
    return [n for n in dict.fromkeys(names) if n.isidentifier() and n != "__pycache__"]


def _requires(metadata: str) -> list[str]:
    out: list[str] = []
    for raw in email.parser.HeaderParser().parsestr(metadata).get_all("Requires-Dist") or []:
        requirement, _, marker = raw.partition(";")
        if _EXTRA_MARKER.search(marker):
            continue
        match = _REQ_NAME.match(requirement.strip())
        if match and canonical(match.group(0)) not in out:
            out.append(canonical(match.group(0)))
    return out


def _read_metadata(dep: Dependency, root: Path) -> None:
    info = _dist_info(root, dep)
    names = _top_level(info) if info else []
    if not names:
        names = _package_dirs(root)
    names.sort(key=lambda n: (n.startswith("_"), n))
    # Merge, never replace: an extra import name can only add matches, a missing one could hide a call.
    dep.import_names = list(dict.fromkeys([*dep.import_names, *names]))
    if info and (info / "METADATA").is_file():
        dep.requires = _requires((info / "METADATA").read_text(encoding="utf-8", errors="replace"))

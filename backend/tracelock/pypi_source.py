"""Fetch a dependency's source from PyPI WITHOUT installing or executing it. OWNER: Mukul.

Scaffold status: STUB returning None (the engine then skips the library-side analysis
and, if a curated entry exists, still works). Build (BRIEF_MUKUL.md, task 2):
 1. Look in tracelock/data/wheels/ first (pre-downloaded seed wheels) and in
    .tracelock/cache/src/<name>-<version>/ (already unpacked).
 2. Else run: python -m pip download <name>==<version> --no-deps --only-binary :all:
    -d .tracelock/cache/dl/ ; on failure retry with --no-binary :all: (sdist).
 3. A wheel is a zip: extract into .tracelock/cache/src/<name>-<version>/.
    An sdist is a tar.gz: extract, then use the inner <name>-<version>/ (or src/) directory.
    Reject archive members with absolute paths or '..' (zip-slip).
 4. Return the directory that contains the top-level package(s), i.e. the one where
    `yaml/__init__.py` or `PIL/__init__.py` lives.
 5. Also refine dep.import_names from <dist>.dist-info/top_level.txt (or RECORD) and
    fill dep.requires from METADATA 'Requires-Dist:' lines (name only, extras/markers stripped).
    Mutate the Dependency in place; the verdict engine uses dep.requires for the transitive rule.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .models import Dependency

DATA_WHEELS = Path(__file__).parent / "data" / "wheels"
CACHE_SRC = Path(".tracelock") / "cache" / "src"


def fetch(dep: Dependency, offline: bool = False) -> Optional[Path]:
    """Return the unpacked source root for dep, or None if unavailable. Stub: None."""
    cached = CACHE_SRC / f"{dep.name}-{dep.version}"
    if cached.exists():
        return cached
    return None

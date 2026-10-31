"""Load a project from a local directory or an uploaded zip into the same workspace layout as GitHub scans.

Files are only copied or extracted; nothing from the project is executed or installed.
Both loaders raise RepositoryFetchError on any failure and leave no partial workspace behind.
"""
import os
import shutil
import stat
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Optional

from app.ingestion.github_loader import (
    IGNORED_DIRS,
    WORKSPACE_ROOT,
    RepositoryFetchError,
    RepositoryMetadata,
    _scan_dir,
    discover_files,
)

MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_FILES = 5_000
_CHUNK = 1024 * 1024
# Skipped inside archives: dependency folders and macOS Finder metadata ("._app.py" is not Python).
_SKIPPED_PARTS = IGNORED_DIRS | {"__MACOSX"}


class _Budget:
    """Running file count and byte total; raises once either cap is exceeded."""

    def __init__(self) -> None:
        self.files = 0
        self.bytes = 0

    def add_file(self) -> None:
        self.files += 1
        if self.files > MAX_FILES:
            raise RepositoryFetchError(f"The project has more than {MAX_FILES} files")

    def add_bytes(self, count: int) -> None:
        self.bytes += count
        if self.bytes > MAX_TOTAL_BYTES:
            raise RepositoryFetchError(f"The project is larger than {MAX_TOTAL_BYTES // (1024 * 1024)} MB")


def upload_path(scan_id: str, workspace_root: Path = WORKSPACE_ROOT) -> Path:
    """Where an uploaded zip waits for the worker. Kept outside the scan dir, which is wiped on fetch."""
    try:
        scan_id = str(uuid.UUID(scan_id))
    except ValueError:
        raise RepositoryFetchError("Invalid scan id") from None
    return workspace_root / "uploads" / f"{scan_id}.zip"


def save_upload(stream: BinaryIO, dest: Path) -> None:
    """Stream an uploaded file to dest, refusing anything over the size cap or not a zip."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    budget = _Budget()
    try:
        with open(dest, "wb") as out:
            while chunk := stream.read(_CHUNK):
                budget.add_bytes(len(chunk))
                out.write(chunk)
        if not zipfile.is_zipfile(dest):
            raise RepositoryFetchError("The uploaded file is not a zip archive")
    except Exception:
        dest.unlink(missing_ok=True)
        raise


def fetch_local_directory(
    scan_id: str, path: str, workspace_root: Path = WORKSPACE_ROOT
) -> RepositoryMetadata:
    """Copy a local project directory into the scan workspace, skipping .git, virtualenvs and symlinks."""
    source = Path(path).expanduser()
    if not source.is_absolute():
        raise RepositoryFetchError("The local path must be absolute")
    source = source.resolve()
    if not source.is_dir():
        raise RepositoryFetchError("The local path is not a directory")

    scan_dir = _scan_dir(workspace_root, scan_id)
    repo_dir = scan_dir / "repository"
    shutil.rmtree(scan_dir, ignore_errors=True)
    scan_dir.mkdir(parents=True)
    try:
        _copy_tree(source, repo_dir, skip=workspace_root.resolve())
        return _metadata(scan_id, str(source), repo_dir)
    except Exception:
        shutil.rmtree(scan_dir, ignore_errors=True)
        raise


def fetch_zip_archive(
    scan_id: str, archive: Path, display_name: str, workspace_root: Path = WORKSPACE_ROOT
) -> RepositoryMetadata:
    """Extract an uploaded zip into the scan workspace.

    Rejects absolute and '..' member paths, caps size and member count, and never creates symlinks.
    A single top-level folder (as GitHub and Finder produce) becomes the project root.
    """
    scan_dir = _scan_dir(workspace_root, scan_id)
    repo_dir = scan_dir / "repository"
    shutil.rmtree(scan_dir, ignore_errors=True)
    scan_dir.mkdir(parents=True)
    try:
        _extract_zip(archive, repo_dir)
        return _metadata(scan_id, display_name, _project_root(repo_dir))
    except zipfile.BadZipFile:
        shutil.rmtree(scan_dir, ignore_errors=True)
        raise RepositoryFetchError("The uploaded file is not a valid zip archive") from None
    except Exception:
        shutil.rmtree(scan_dir, ignore_errors=True)
        raise


def _copy_tree(source: Path, dest: Path, skip: Path) -> None:
    budget = _Budget()
    dest.mkdir(parents=True)
    for current, dirs, files in os.walk(source):  # does not follow symlinked directories
        current = Path(current)
        # `skip` keeps a parent of the workspace from copying the workspace into itself.
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_DIRS and not (current / d).is_symlink() and (current / d).resolve() != skip
        ]
        target_dir = dest / current.relative_to(source)
        target_dir.mkdir(exist_ok=True)
        for name in files:
            src = current / name
            if src.is_symlink() or not src.is_file():
                continue
            budget.add_file()
            budget.add_bytes(src.stat().st_size)
            shutil.copyfile(src, target_dir / name)


def _extract_zip(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True)
    budget = _Budget()
    with zipfile.ZipFile(archive) as zf:
        members = zf.infolist()
        if len(members) > MAX_FILES:
            raise RepositoryFetchError(f"The archive has more than {MAX_FILES} entries")
        for member in members:
            relative = _safe_member_path(member.filename)
            if relative is None or stat.S_ISLNK(member.external_attr >> 16):
                continue
            target = dest.joinpath(*relative.parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            budget.add_file()
            target.parent.mkdir(parents=True, exist_ok=True)
            # Count bytes actually written: declared sizes in the zip header can lie.
            with zf.open(member) as src, open(target, "wb") as out:
                while chunk := src.read(_CHUNK):
                    budget.add_bytes(len(chunk))
                    out.write(chunk)


def _safe_member_path(name: str) -> Optional[PurePosixPath]:
    """The member's relative path, None to skip it, or RepositoryFetchError if it escapes the root."""
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
        raise RepositoryFetchError(f"The archive contains an unsafe path: {name[:200]}")
    parts = [part for part in path.parts if part != "."]
    if not parts or any(part in _SKIPPED_PARTS for part in parts):
        return None
    return PurePosixPath(*parts)


def _project_root(repo_dir: Path) -> Path:
    entries = list(repo_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return repo_dir


def _metadata(scan_id: str, source: str, repo_dir: Path) -> RepositoryMetadata:
    python_files, manifest_files = discover_files(repo_dir)
    return RepositoryMetadata(
        scan_id=scan_id,
        repository_url=source,
        ref="",
        commit_sha="",
        workspace_path=str(repo_dir),
        python_files=python_files,
        manifest_files=manifest_files,
        python_file_count=len(python_files),
    )

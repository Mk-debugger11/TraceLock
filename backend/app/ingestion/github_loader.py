import logging
import os
import re
import shutil
import signal
import subprocess
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from app.models.scan import STATUS_READY_FOR_ANALYSIS
from app.schemas.scan import normalize_repository_url, validate_ref

logger = logging.getLogger(__name__)

# Layout: <WORKSPACE_ROOT>/scans/<scan_id>/repository
WORKSPACE_ROOT = Path(
    os.environ.get("TRACELOCK_WORKSPACE_ROOT", Path(__file__).resolve().parents[2] / "workspace")
)
GIT_TIMEOUT_SECONDS = 120

IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build"}
MANIFEST_FILES = {"requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock"}
_FULL_SHA_RE = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")


class RepositoryFetchError(Exception):
    """Fetching failed. The message is safe to show to the user."""


@dataclass
class RepositoryMetadata:
    scan_id: str
    repository_url: str
    ref: str
    commit_sha: str
    workspace_path: str  # the repository root
    python_files: List[str]  # paths relative to the repository root
    manifest_files: List[str]
    python_file_count: int
    status: str = STATUS_READY_FOR_ANALYSIS

    def to_dict(self) -> dict:
        return asdict(self)


def fetch_repository(
    scan_id: str, repository_url: str, ref: str, workspace_root: Path = WORKSPACE_ROOT
) -> RepositoryMetadata:
    """Fetch one revision of a public GitHub repo into its own workspace and list its Python files.

    Only runs git; nothing from the repository is executed or installed.
    Raises RepositoryFetchError on any failure and leaves no partial workspace behind.
    """
    try:
        url = normalize_repository_url(repository_url)
    except ValueError as exc:
        raise RepositoryFetchError(f"Invalid repository URL: {exc}") from None
    try:
        ref = validate_ref(ref)
    except ValueError as exc:
        raise RepositoryFetchError(f"Invalid ref: {exc}") from None

    scan_dir = _scan_dir(workspace_root, scan_id)
    repo_dir = scan_dir / "repository"
    shutil.rmtree(scan_dir, ignore_errors=True)  # retrying the same scan starts clean
    scan_dir.mkdir(parents=True)

    try:
        commit_sha = _checkout(f"{url}.git", ref, repo_dir)
        python_files, manifest_files = discover_files(repo_dir)
    except Exception:
        shutil.rmtree(scan_dir, ignore_errors=True)
        raise

    return RepositoryMetadata(
        scan_id=scan_id,
        repository_url=url,
        ref=ref,
        commit_sha=commit_sha,
        workspace_path=str(repo_dir),
        python_files=python_files,
        manifest_files=manifest_files,
        python_file_count=len(python_files),
    )


def discover_files(repo_dir: Path) -> Tuple[List[str], List[str]]:
    """Return (python files, dependency manifests) as sorted paths relative to repo_dir."""
    python_files, manifest_files = [], []
    for current, dirs, files in os.walk(repo_dir):  # does not follow symlinked directories
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            relative = path.relative_to(repo_dir).as_posix()
            if name.endswith(".py"):
                python_files.append(relative)
            elif name in MANIFEST_FILES:
                manifest_files.append(relative)
    return sorted(python_files), sorted(manifest_files)


def _scan_dir(workspace_root: Path, scan_id: str) -> Path:
    """The scan's own directory, guaranteed to sit directly inside <workspace_root>/scans."""
    try:
        scan_id = str(uuid.UUID(scan_id))  # only UUIDs: no "..", "/" or other path tricks
    except ValueError:
        raise RepositoryFetchError("Invalid scan id") from None
    scans_root = (workspace_root / "scans").resolve()
    scan_dir = (scans_root / scan_id).resolve()
    if scan_dir.parent != scans_root:
        raise RepositoryFetchError("Invalid scan workspace path")
    return scan_dir


def _checkout(remote: str, ref: str, repo_dir: Path) -> str:
    """Fetch exactly `ref` (shallow) into repo_dir and return the resolved commit SHA."""
    if _FULL_SHA_RE.fullmatch(ref):
        _run_git(["init", "--quiet", str(repo_dir)])
        _run_git(["remote", "add", "origin", remote], cwd=repo_dir)
        _run_git(["fetch", "--depth", "1", "--no-tags", "--no-recurse-submodules", "origin", ref], cwd=repo_dir)
        _run_git(["checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=repo_dir)
    else:
        _run_git(
            ["clone", "--depth", "1", "--no-tags", "--single-branch", "--branch", ref, "--", remote, str(repo_dir)]
        )

    commit_sha = _run_git(["rev-parse", "HEAD"], cwd=repo_dir)
    if _FULL_SHA_RE.fullmatch(ref) and commit_sha != ref.lower():
        raise RepositoryFetchError("The checked-out commit does not match the requested commit")
    return commit_sha


def _run_git(args: List[str], cwd: Optional[Path] = None) -> str:
    """Run `git <args>` (never through a shell) and return stdout."""
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",  # fail instead of asking for credentials
        "GIT_CONFIG_NOSYSTEM": "1",  # ignore system/global config, so no stored credentials are used
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_LFS_SKIP_SMUDGE": "1",
    }
    # core.symlinks=false checks symlinks out as plain files, so a repo can't point us outside the workspace.
    command = ["git", "-c", "core.symlinks=false", *args]
    try:
        # Own process group, so a timeout can kill git's helper processes too.
        proc = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError:
        raise RepositoryFetchError("Git is not installed on the server") from None

    try:
        stdout, stderr = proc.communicate(timeout=GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise RepositoryFetchError("Timed out while fetching the repository") from None

    if proc.returncode != 0:
        logger.warning("git %s failed: %s", args[0], stderr.strip()[:500])
        raise RepositoryFetchError(_explain_git_error(stderr))
    return stdout.strip()


def _explain_git_error(stderr: str) -> str:
    stderr = stderr.lower()
    if any(m in stderr for m in ("remote branch", "couldn't find remote ref", "not our ref", "unadvertised object")):
        return "The requested branch or commit was not found in the repository"
    return "Could not access the repository. Make sure it exists and is public."

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from app.ingestion import github_loader
from app.ingestion.github_loader import RepositoryFetchError, discover_files, fetch_repository

SCAN_ID = "11111111-1111-4111-8111-111111111111"
OTHER_SCAN_ID = "22222222-2222-4222-8222-222222222222"
URL = "https://github.com/owner/repo"
SHA = "a" * 40


class FakeGit:
    """Stands in for _run_git: records commands and creates the files a clone would."""

    def __init__(self, files=("app.py",), head=SHA):
        self.files = files
        self.head = head
        self.calls = []

    def __call__(self, args, cwd=None):
        self.calls.append(list(args))
        if args[0] in ("clone", "init"):
            dest = Path(args[-1])
            for name in self.files:
                (dest / name).parent.mkdir(parents=True, exist_ok=True)
                (dest / name).write_text("")
        if args[0] == "rev-parse":
            return self.head
        return ""


@pytest.fixture()
def fake_git(monkeypatch):
    fake = FakeGit()
    monkeypatch.setattr(github_loader, "_run_git", fake)
    return fake


# --- git commands ------------------------------------------------------------


def test_branch_uses_shallow_single_branch_clone(tmp_path, fake_git):
    meta = fetch_repository(SCAN_ID, URL, "main", tmp_path)

    repo_dir = str(tmp_path / "scans" / SCAN_ID / "repository")
    assert fake_git.calls[0] == [
        "clone", "--depth", "1", "--no-tags", "--single-branch", "--branch", "main",
        "--", "https://github.com/owner/repo.git", repo_dir,
    ]  # fmt: skip
    assert meta.commit_sha == SHA and meta.ref == "main"
    assert meta.workspace_path == repo_dir


def test_full_sha_is_fetched_and_checked_out_detached(tmp_path, fake_git):
    meta = fetch_repository(SCAN_ID, URL, SHA, tmp_path)

    assert [c[0] for c in fake_git.calls] == ["init", "remote", "fetch", "checkout", "rev-parse"]
    assert fake_git.calls[1][:3] == ["remote", "add", "origin"]
    assert fake_git.calls[2] == [
        "fetch", "--depth", "1", "--no-tags", "--no-recurse-submodules", "origin", SHA,
    ]  # fmt: skip
    assert fake_git.calls[3] == ["checkout", "--quiet", "--detach", "FETCH_HEAD"]
    assert meta.commit_sha == SHA


def test_wrong_commit_checked_out_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(github_loader, "_run_git", FakeGit(head="b" * 40))
    with pytest.raises(RepositoryFetchError, match="does not match"):
        fetch_repository(SCAN_ID, URL, SHA, tmp_path)
    assert not (tmp_path / "scans" / SCAN_ID).exists()


def test_url_is_normalized(tmp_path, fake_git):
    meta = fetch_repository(SCAN_ID, "https://www.github.com/owner/repo.git/", "main", tmp_path)
    assert meta.repository_url == URL
    assert fake_git.calls[0][-2] == "https://github.com/owner/repo.git"


# --- validation --------------------------------------------------------------


@pytest.mark.parametrize(
    "url", ["https://gitlab.com/owner/repo", "http://github.com/owner/repo", "git@github.com:owner/repo.git", "owner/repo"]
)
def test_invalid_url_runs_no_git(tmp_path, fake_git, url):
    with pytest.raises(RepositoryFetchError, match="Invalid repository URL"):
        fetch_repository(SCAN_ID, url, "main", tmp_path)
    assert fake_git.calls == []


@pytest.mark.parametrize("ref", ["", "--upload-pack=evil", "-x", "bad branch", "a..b", "x;rm -rf /"])
def test_invalid_ref_runs_no_git(tmp_path, fake_git, ref):
    with pytest.raises(RepositoryFetchError, match="Invalid ref"):
        fetch_repository(SCAN_ID, URL, ref, tmp_path)
    assert fake_git.calls == []


# --- git failures (a fake `git` executable on PATH) --------------------------


def install_fake_git(monkeypatch, tmp_path, script):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    git = bin_dir / "git"
    git.write_text(f"#!/bin/sh\n{script}\n")
    git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")


def test_repository_that_does_not_exist(tmp_path, monkeypatch):
    install_fake_git(
        monkeypatch, tmp_path, "echo \"fatal: could not read Username for 'https://github.com': terminal prompts disabled\" >&2; exit 128"
    )
    with pytest.raises(RepositoryFetchError, match="Make sure it exists and is public"):
        fetch_repository(SCAN_ID, URL, "main", tmp_path / "ws")
    assert not (tmp_path / "ws" / "scans" / SCAN_ID).exists()


def test_branch_that_does_not_exist(tmp_path, monkeypatch):
    install_fake_git(monkeypatch, tmp_path, "echo 'fatal: Remote branch nope not found in upstream origin' >&2; exit 128")
    with pytest.raises(RepositoryFetchError, match="branch or commit was not found"):
        fetch_repository(SCAN_ID, URL, "nope", tmp_path / "ws")


def test_git_timeout_kills_git_and_cleans_up(tmp_path, monkeypatch):
    install_fake_git(monkeypatch, tmp_path, "sleep 30")
    monkeypatch.setattr(github_loader, "GIT_TIMEOUT_SECONDS", 0.3)

    with pytest.raises(RepositoryFetchError, match="Timed out"):
        fetch_repository(SCAN_ID, URL, "main", tmp_path / "ws")
    assert not (tmp_path / "ws" / "scans" / SCAN_ID).exists()


def test_clone_failure_cleans_up_partial_workspace(tmp_path, monkeypatch):
    def failing_clone(args, cwd=None):
        (Path(args[-1])).mkdir(parents=True)  # git leaves a partial checkout behind
        raise RepositoryFetchError("Could not access the repository. Make sure it exists and is public.")

    monkeypatch.setattr(github_loader, "_run_git", failing_clone)
    with pytest.raises(RepositoryFetchError):
        fetch_repository(SCAN_ID, URL, "main", tmp_path)
    assert not (tmp_path / "scans" / SCAN_ID).exists()


def test_git_not_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(RepositoryFetchError, match="not installed"):
        fetch_repository(SCAN_ID, URL, "main", tmp_path / "ws")


# --- workspace isolation -----------------------------------------------------


@pytest.mark.parametrize("scan_id", ["../../etc", "..", "../escape", "/etc/passwd", "not-a-uuid", ""])
def test_scan_id_cannot_escape_workspace(tmp_path, fake_git, scan_id):
    with pytest.raises(RepositoryFetchError, match="Invalid scan"):
        fetch_repository(scan_id, URL, "main", tmp_path / "ws")
    assert fake_git.calls == []
    assert not (tmp_path / "ws").exists() and not (tmp_path / "escape").exists()


def test_each_scan_gets_its_own_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(github_loader, "_run_git", FakeGit(files=("one.py",)))
    first = fetch_repository(SCAN_ID, URL, "main", tmp_path)
    monkeypatch.setattr(github_loader, "_run_git", FakeGit(files=("two.py",)))
    second = fetch_repository(OTHER_SCAN_ID, URL, "main", tmp_path)

    assert first.workspace_path != second.workspace_path
    assert first.python_files == ["one.py"] and second.python_files == ["two.py"]
    assert (Path(first.workspace_path) / "one.py").exists()  # the second fetch left the first alone
    assert not (Path(first.workspace_path) / "two.py").exists()


def test_retrying_a_scan_starts_from_a_clean_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(github_loader, "_run_git", FakeGit(files=("old.py",)))
    fetch_repository(SCAN_ID, URL, "main", tmp_path)
    monkeypatch.setattr(github_loader, "_run_git", FakeGit(files=("new.py",)))
    meta = fetch_repository(SCAN_ID, URL, "main", tmp_path)
    assert meta.python_files == ["new.py"]


# --- file discovery ----------------------------------------------------------


def test_repository_without_python_files(tmp_path, monkeypatch):
    monkeypatch.setattr(github_loader, "_run_git", FakeGit(files=("README.md", "index.js")))
    meta = fetch_repository(SCAN_ID, URL, "main", tmp_path)
    assert meta.python_files == [] and meta.manifest_files == [] and meta.python_file_count == 0
    assert meta.status == "ready_for_analysis"


def test_multiple_python_files_and_manifests(tmp_path, monkeypatch):
    files = (
        "app.py", "services.py", "pkg/utils.py", "pkg/sub/deep.py",
        "requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock", "Pipfile.lock",
        "services/api/requirements.txt", "README.md", "notes.txt",
    )  # fmt: skip
    monkeypatch.setattr(github_loader, "_run_git", FakeGit(files=files))

    meta = fetch_repository(SCAN_ID, URL, "main", tmp_path)

    assert meta.python_files == ["app.py", "pkg/sub/deep.py", "pkg/utils.py", "services.py"]
    assert meta.manifest_files == [
        "Pipfile.lock", "poetry.lock", "pyproject.toml", "requirements.txt", "services/api/requirements.txt", "uv.lock",
    ]  # fmt: skip
    assert meta.python_file_count == 4
    assert meta.to_dict()["workspace_path"] == meta.workspace_path


def test_ignored_directories_are_skipped(tmp_path):
    for path in [
        "keep.py", ".git/hooks.py", ".venv/lib.py", "venv/lib.py", "__pycache__/x.py",
        "node_modules/pkg/setup.py", "dist/gen.py", "build/gen.py", "src/venv/requirements.txt", "src/ok.py",
    ]:  # fmt: skip
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text("")

    assert discover_files(tmp_path) == (["keep.py", "src/ok.py"], [])


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "real.py").write_text("")
    (repo / "link.py").symlink_to(outside / "secret.py")
    (repo / "linkdir").symlink_to(outside, target_is_directory=True)

    assert discover_files(repo) == (["real.py"], [])


# --- integration: real git against a local repository ------------------------


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
class TestWithRealGit:
    """Uses a throwaway local repo; git redirects https://github.com/ to it, so no network is needed."""

    @pytest.fixture()
    def remote(self, tmp_path, monkeypatch):
        remotes = tmp_path / "remotes"
        repo = remotes / "owner" / "repo.git"
        repo.mkdir(parents=True)

        def git(*args):
            result = subprocess.run(
                ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
                cwd=repo, capture_output=True, text=True, check=True,
            )  # fmt: skip
            return result.stdout.strip()

        git("init", "-q", "-b", "main")
        (repo / "app.py").write_text("print('main')\n")
        (repo / "requirements.txt").write_text("flask==3.0.3\n")
        (repo / "node_modules").mkdir()
        (repo / "node_modules" / "ignored.py").write_text("")
        git("add", "-A")
        git("commit", "-q", "-m", "first")
        first_sha = git("rev-parse", "HEAD")

        git("checkout", "-q", "-b", "dev")
        (repo / "extra.py").write_text("print('dev')\n")
        git("add", "-A")
        git("commit", "-q", "-m", "second")
        dev_sha = git("rev-parse", "HEAD")
        git("checkout", "-q", "main")

        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", f"url.file://{remotes}/.insteadOf")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://github.com/")
        return {"first": first_sha, "dev": dev_sha}

    def test_branch_selection(self, tmp_path, remote):
        main = fetch_repository(SCAN_ID, URL, "main", tmp_path / "ws")
        dev = fetch_repository(OTHER_SCAN_ID, URL, "dev", tmp_path / "ws")

        assert main.commit_sha == remote["first"] and dev.commit_sha == remote["dev"]
        assert main.python_files == ["app.py"]
        assert dev.python_files == ["app.py", "extra.py"]
        assert main.manifest_files == ["requirements.txt"]
        assert (Path(main.workspace_path) / ".git").is_dir()

    def test_full_commit_sha_selection(self, tmp_path, remote):
        meta = fetch_repository(SCAN_ID, URL, remote["dev"], tmp_path / "ws")
        assert meta.commit_sha == remote["dev"]
        assert meta.python_files == ["app.py", "extra.py"]
        head = subprocess.run(
            ["git", "symbolic-ref", "-q", "HEAD"], cwd=meta.workspace_path, capture_output=True
        )
        assert head.returncode != 0  # detached HEAD

    def test_unknown_branch_and_commit(self, tmp_path, remote):
        with pytest.raises(RepositoryFetchError, match="not found"):
            fetch_repository(SCAN_ID, URL, "no-such-branch", tmp_path / "ws")
        with pytest.raises(RepositoryFetchError):
            fetch_repository(SCAN_ID, URL, "f" * 40, tmp_path / "ws")
        assert not (tmp_path / "ws" / "scans" / SCAN_ID).exists()

    def test_unknown_repository(self, tmp_path, remote):
        with pytest.raises(RepositoryFetchError, match="exists and is public"):
            fetch_repository(SCAN_ID, "https://github.com/owner/missing", "main", tmp_path / "ws")

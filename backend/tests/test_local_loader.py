import io
import os
import stat
import uuid
import zipfile

import pytest

from app.ingestion import local_loader
from app.ingestion.github_loader import RepositoryFetchError
from app.ingestion.local_loader import fetch_local_directory, fetch_zip_archive, save_upload


def make_zip(path, members):
    """members: {name: bytes} or {name: (bytes, external_attr)}."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            if isinstance(data, tuple):
                data, info.external_attr = data
            zf.writestr(info, data)
    return path


@pytest.fixture()
def scan_id():
    return str(uuid.uuid4())


# --- local directory ---------------------------------------------------------


def test_local_directory_copies_project_and_skips_ignored(tmp_path, scan_id):
    src = tmp_path / "project"
    (src / "pkg").mkdir(parents=True)
    (src / "app.py").write_text("import yaml\n")
    (src / "pkg" / "util.py").write_text("")
    (src / "requirements.txt").write_text("pyyaml==5.3\n")
    for ignored in (".git", ".venv", "node_modules"):
        (src / ignored).mkdir()
        (src / ignored / "x.py").write_text("")
    secret = tmp_path / "secret.txt"
    secret.write_text("do not copy")
    os.symlink(secret, src / "link.txt")
    os.symlink(tmp_path, src / "linkdir")

    meta = fetch_local_directory(scan_id, str(src), workspace_root=tmp_path / "ws")

    repo = tmp_path / "ws" / "scans" / scan_id / "repository"
    assert meta.workspace_path == str(repo)
    assert meta.repository_url == str(src.resolve())
    assert meta.python_files == ["app.py", "pkg/util.py"]
    assert meta.manifest_files == ["requirements.txt"]
    assert not (repo / ".git").exists() and not (repo / ".venv").exists() and not (repo / "node_modules").exists()
    assert not (repo / "link.txt").exists() and not (repo / "linkdir").exists()
    assert (src / "app.py").exists()  # source left untouched


@pytest.mark.parametrize("path", ["relative/dir", "/definitely/not/here"])
def test_local_directory_rejects_bad_paths(tmp_path, scan_id, path):
    with pytest.raises(RepositoryFetchError):
        fetch_local_directory(scan_id, path, workspace_root=tmp_path / "ws")


def test_local_directory_size_cap_cleans_up(tmp_path, scan_id, monkeypatch):
    src = tmp_path / "project"
    src.mkdir()
    (src / "big.py").write_bytes(b"x" * 200)
    monkeypatch.setattr(local_loader, "MAX_TOTAL_BYTES", 100)

    with pytest.raises(RepositoryFetchError, match="larger than"):
        fetch_local_directory(scan_id, str(src), workspace_root=tmp_path / "ws")
    assert not (tmp_path / "ws" / "scans" / scan_id).exists()


# --- zip archive -------------------------------------------------------------


def test_zip_extracts_and_unwraps_single_top_folder(tmp_path, scan_id):
    archive = make_zip(
        tmp_path / "p.zip",
        {
            "proj/app.py": b"import yaml\n",
            "proj/requirements.txt": b"pyyaml==5.3\n",
            "proj/.venv/lib/x.py": b"",
            "__MACOSX/proj/._app.py": b"\x00\x05",
        },
    )

    meta = fetch_zip_archive(scan_id, archive, "p.zip", workspace_root=tmp_path / "ws")

    assert meta.workspace_path == str(tmp_path / "ws" / "scans" / scan_id / "repository" / "proj")
    assert meta.repository_url == "p.zip"
    assert meta.python_files == ["app.py"]
    assert meta.manifest_files == ["requirements.txt"]


@pytest.mark.parametrize("bad", ["../evil.py", "proj/../../evil.py", "/etc/evil.py", "C:/evil.py", "..\\evil.py"])
def test_zip_rejects_escaping_paths(tmp_path, scan_id, bad):
    archive = make_zip(tmp_path / "p.zip", {"ok.py": b"", bad: b"pwned"})

    with pytest.raises(RepositoryFetchError, match="unsafe path"):
        fetch_zip_archive(scan_id, archive, "p.zip", workspace_root=tmp_path / "ws")
    assert not (tmp_path / "ws" / "scans" / scan_id).exists()
    assert not (tmp_path / "evil.py").exists() and not (tmp_path / "ws" / "evil.py").exists()


def test_zip_never_creates_symlinks(tmp_path, scan_id):
    link_attr = (stat.S_IFLNK | 0o777) << 16
    archive = make_zip(tmp_path / "p.zip", {"app.py": b"", "passwd": (b"/etc/passwd", link_attr)})

    meta = fetch_zip_archive(scan_id, archive, "p.zip", workspace_root=tmp_path / "ws")

    repo = tmp_path / "ws" / "scans" / scan_id / "repository"
    assert meta.python_files == ["app.py"]
    assert not (repo / "passwd").exists() and not (repo / "passwd").is_symlink()


def test_zip_size_cap_counts_real_bytes(tmp_path, scan_id, monkeypatch):
    archive = make_zip(tmp_path / "p.zip", {"a.py": b"x" * 80, "b.py": b"x" * 80})
    monkeypatch.setattr(local_loader, "MAX_TOTAL_BYTES", 100)

    with pytest.raises(RepositoryFetchError, match="larger than"):
        fetch_zip_archive(scan_id, archive, "p.zip", workspace_root=tmp_path / "ws")
    assert not (tmp_path / "ws" / "scans" / scan_id).exists()


def test_zip_member_count_cap(tmp_path, scan_id, monkeypatch):
    archive = make_zip(tmp_path / "p.zip", {f"m{i}.py": b"" for i in range(4)})
    monkeypatch.setattr(local_loader, "MAX_FILES", 3)

    with pytest.raises(RepositoryFetchError, match="more than 3"):
        fetch_zip_archive(scan_id, archive, "p.zip", workspace_root=tmp_path / "ws")


def test_corrupt_zip_is_a_fetch_error(tmp_path, scan_id):
    archive = tmp_path / "p.zip"
    archive.write_bytes(b"PK\x03\x04 not really a zip")
    with pytest.raises(RepositoryFetchError, match="not a valid zip"):
        fetch_zip_archive(scan_id, archive, "p.zip", workspace_root=tmp_path / "ws")


# --- upload ------------------------------------------------------------------


def test_save_upload_rejects_non_zip_and_oversize(tmp_path, monkeypatch):
    dest = tmp_path / "uploads" / "x.zip"
    with pytest.raises(RepositoryFetchError, match="not a zip"):
        save_upload(io.BytesIO(b"hello"), dest)
    assert not dest.exists()

    monkeypatch.setattr(local_loader, "MAX_TOTAL_BYTES", 10)
    with pytest.raises(RepositoryFetchError, match="larger than"):
        save_upload(io.BytesIO(b"x" * 11), dest)
    assert not dest.exists()


def test_upload_path_requires_uuid(tmp_path):
    with pytest.raises(RepositoryFetchError):
        local_loader.upload_path("../../etc", workspace_root=tmp_path)

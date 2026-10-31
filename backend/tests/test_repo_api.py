import io
import subprocess
import zipfile
from types import SimpleNamespace


def fake_git(stdout="", returncode=0):
    def run(cmd, **kwargs):
        assert cmd[:3] == ["git", "ls-remote", "--heads"]
        return SimpleNamespace(stdout=stdout, returncode=returncode)

    return run


def test_branches(client, monkeypatch):
    out = "abc\trefs/heads/main\ndef\trefs/heads/feature/x\n"
    monkeypatch.setattr(subprocess, "run", fake_git(out))

    res = client.post("/api/branches", json={"repo_url": "owner/repo"})

    assert res.status_code == 200
    assert res.json() == {"branches": ["main", "feature/x"]}


def test_branches_inaccessible_repo(client, monkeypatch):
    monkeypatch.setattr(subprocess, "run", fake_git(returncode=128))
    res = client.post("/api/branches", json={"repo_url": "https://github.com/owner/missing"})
    assert res.status_code == 400
    assert "Could not access" in res.json()["error"]


def test_branches_rejects_non_github_url(client):
    res = client.post("/api/branches", json={"repo_url": "https://evil.com/owner/repo"})
    assert res.status_code == 400


def test_branches_missing_repo_url(client):
    res = client.post("/api/branches", json={})
    assert res.status_code == 422
    assert res.json() == {"error": "repo_url is required"}


def zip_bytes(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_analyze_github_queues_scan(client):
    res = client.post(
        "/api/analyze",
        data={"repo_type": "github", "repo_url": "https://github.com/owner/repo.git", "branch": "main"},
    )
    assert res.status_code == 202
    scan = client.get(f"/api/scans/{res.json()['scan_id']}").json()
    assert (scan["source_type"], scan["repository_url"], scan["ref"], scan["status"]) == (
        "github", "https://github.com/owner/repo", "main", "queued"
    )


def test_analyze_github_rejects_bad_url(client):
    res = client.post("/api/analyze", data={"repo_type": "github", "repo_url": "https://evil.com/a/b", "branch": "main"})
    assert res.status_code == 422
    assert "GitHub repository URL" in res.json()["error"]


def test_analyze_upload_saves_zip_and_queues_scan(client, workspace):
    res = client.post(
        "/api/analyze",
        data={"repo_type": "upload", "branch": "main", "scan_mode": "full"},
        files={"repo_file": ("../../project.zip", zip_bytes({"app.py": "print(1)\n"}))},
    )
    assert res.status_code == 202
    scan_id = res.json()["scan_id"]
    assert (workspace / "uploads" / f"{scan_id}.zip").is_file()
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert (scan["source_type"], scan["repository_url"], scan["status"]) == ("upload", "project.zip", "queued")


def test_analyze_upload_rejects_non_zip(client, workspace):
    res = client.post("/api/analyze", data={"repo_type": "upload"}, files={"repo_file": ("p.zip", b"nope")})
    assert res.status_code == 400
    assert "not a zip" in res.json()["error"]
    assert not any((workspace / "uploads").iterdir())


def test_analyze_local_disabled_by_default(client, tmp_path, monkeypatch):
    monkeypatch.delenv("TRACELOCK_ALLOW_LOCAL_PATHS", raising=False)
    res = client.post("/api/analyze", data={"repo_type": "local", "path": str(tmp_path)})
    assert res.status_code == 403


def test_analyze_local_queues_scan(client, tmp_path, monkeypatch):
    monkeypatch.setenv("TRACELOCK_ALLOW_LOCAL_PATHS", "1")
    res = client.post("/api/analyze", data={"repo_type": "local", "path": str(tmp_path)})
    assert res.status_code == 202
    scan = client.get(f"/api/scans/{res.json()['scan_id']}").json()
    assert (scan["source_type"], scan["repository_url"]) == ("local", str(tmp_path.resolve()))

    bad = client.post("/api/analyze", data={"repo_type": "local", "path": "relative/path"})
    assert bad.status_code == 400


def test_analyze_rejects_unknown_repo_type(client):
    assert client.post("/api/analyze", data={"repo_type": "ftp"}).status_code == 422

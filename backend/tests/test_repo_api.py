import subprocess
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


def test_analyze_accepts_frontend_form_data(client):
    res = client.post(
        "/api/analyze",
        data={"repo_type": "upload", "branch": "main", "scan_mode": "full"},
        files={"repo_file": ("project.zip", b"zipbytes")},
    )
    assert res.status_code == 200
    assert res.json()["received_data"] == {
        "repo_type": "upload",
        "repo_url": None,
        "uploaded_file": "project.zip",
        "branch": "main",
        "scan_mode": "full",
    }

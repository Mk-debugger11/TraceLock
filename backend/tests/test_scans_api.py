import uuid

import pytest
from sqlalchemy.exc import OperationalError

from app.models.scan import Scan

VALID = {"repository_url": "https://github.com/owner/repository", "ref": "main"}


def test_create_scan(client, session_factory):
    res = client.post("/api/scans", json=VALID)

    assert res.status_code == 202
    body = res.json()
    uuid.UUID(body["scan_id"])
    assert body == {
        "scan_id": body["scan_id"],
        "status": "queued",
        "stage": "queued",
        "progress": 0,
        "message": "Repository scan queued successfully",
    }
    with session_factory() as db:
        scan = db.get(Scan, body["scan_id"])
        assert (scan.repository_url, scan.ref) == (VALID["repository_url"], "main")
        assert scan.commit_sha is None and scan.workspace_path is None and scan.error_message is None


def test_scan_ids_are_unique(client):
    ids = {client.post("/api/scans", json=VALID).json()["scan_id"] for _ in range(2)}
    assert len(ids) == 2


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/owner/repository/",
        "https://github.com/owner/repository.git",
        "https://www.github.com/owner/repository",
    ],
)
def test_url_is_normalized(client, url):
    scan_id = client.post("/api/scans", json={**VALID, "repository_url": url}).json()["scan_id"]
    assert client.get(f"/api/scans/{scan_id}").json()["repository_url"] == VALID["repository_url"]


@pytest.mark.parametrize(
    "url",
    [
        "",
        "owner/repository",
        "http://github.com/owner/repository",
        "https://gitlab.com/owner/repository",
        "https://github.com.evil.com/owner/repository",
        "https://user@github.com/owner/repository",
        "https://github.com/owner",
        "https://github.com/owner/repository/tree/main",
        "https://github.com/owner/repository?tab=readme",
        "https://github.com/owner/..",
    ],
)
def test_invalid_repository_url(client, url):
    res = client.post("/api/scans", json={**VALID, "repository_url": url})
    assert res.status_code == 422
    assert res.json()["error"].startswith("repository_url")


@pytest.mark.parametrize("ref", ["main", "feature/login", "v1.0", "a" * 40])
def test_valid_ref(client, ref):
    assert client.post("/api/scans", json={**VALID, "ref": ref}).status_code == 202


@pytest.mark.parametrize(
    "ref", ["", "   ", "--upload-pack=x", "bad branch", "bad..name", "bad~1", "bad:name", "trailing/", "a" * 256]
)
def test_invalid_ref(client, ref):
    res = client.post("/api/scans", json={**VALID, "ref": ref})
    assert res.status_code == 422
    assert res.json()["error"].startswith("ref")


@pytest.mark.parametrize(
    "payload, error",
    [
        ({}, "repository_url is required; ref is required"),
        ({"ref": "main"}, "repository_url is required"),
        ({"repository_url": VALID["repository_url"]}, "ref is required"),
    ],
)
def test_missing_fields(client, payload, error):
    res = client.post("/api/scans", json=payload)
    assert res.status_code == 422
    assert res.json() == {"error": error}


def test_invalid_input_creates_no_record(client, session_factory):
    client.post("/api/scans", json={**VALID, "ref": ""})
    with session_factory() as db:
        assert db.query(Scan).count() == 0


def test_get_scan(client):
    scan_id = client.post("/api/scans", json=VALID).json()["scan_id"]

    res = client.get(f"/api/scans/{scan_id}")

    assert res.status_code == 200
    assert res.json() == {
        "scan_id": scan_id,
        "repository_url": VALID["repository_url"],
        "ref": "main",
        "status": "queued",
        "stage": "queued",
        "progress": 0,
        "error": None,
        "commit_sha": None,
        "python_file_count": None,
        "manifest_files": None,
    }


def test_get_nonexistent_scan(client):
    res = client.get(f"/api/scans/{uuid.uuid4()}")
    assert res.status_code == 404
    assert res.json() == {"error": "Scan not found"}


def test_database_error_is_hidden(client, monkeypatch):
    def boom(self):
        raise OperationalError("INSERT ...", {}, Exception("disk I/O error: /secret/path"))

    monkeypatch.setattr("sqlalchemy.orm.Session.commit", boom)

    res = client.post("/api/scans", json=VALID)

    assert res.status_code == 500
    assert res.json() == {"error": "Database error, please try again later"}

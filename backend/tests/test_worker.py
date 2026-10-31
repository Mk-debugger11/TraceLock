from app.ingestion.github_loader import RepositoryFetchError, RepositoryMetadata
from app.models.scan import Scan
from app.services import scan_service
from app.worker import process_scan

URL = "https://github.com/owner/repo"
SHA = "c" * 40


def make_metadata(scan_id):
    return RepositoryMetadata(
        scan_id=scan_id,
        repository_url=URL,
        ref="main",
        commit_sha=SHA,
        workspace_path=f"/ws/scans/{scan_id}/repository",
        python_files=["app.py", "utils.py"],
        manifest_files=["requirements.txt"],
        python_file_count=2,
    )


def test_claim_moves_scan_to_running(client, session_factory):
    scan_id = client.post("/api/scans", json={"repository_url": URL, "ref": "main"}).json()["scan_id"]

    with session_factory() as db:
        scan = scan_service.claim_next_queued_scan(db)
        assert scan.id == scan_id
        assert (scan.status, scan.stage, scan.progress) == ("running", "repository_fetch", 15)
        assert scan_service.claim_next_queued_scan(db) is None  # nothing left to claim

    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "running"


def test_claims_oldest_scan_first(client, session_factory):
    first = client.post("/api/scans", json={"repository_url": URL, "ref": "main"}).json()["scan_id"]
    client.post("/api/scans", json={"repository_url": URL, "ref": "dev"})
    with session_factory() as db:
        assert scan_service.claim_next_queued_scan(db).id == first


def test_successful_fetch_updates_scan(client, session_factory, monkeypatch):
    scan_id = client.post("/api/scans", json={"repository_url": URL, "ref": "main"}).json()["scan_id"]
    calls = []

    def fake_fetch(sid, url, ref):
        calls.append((sid, url, ref))
        return make_metadata(sid)

    monkeypatch.setattr("app.worker.fetch_repository", fake_fetch)

    with session_factory() as db:
        process_scan(db, scan_service.claim_next_queued_scan(db))

    assert calls == [(scan_id, URL, "main")]
    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["status"] == "ready_for_analysis"
    assert body["stage"] == "repository_fetched"
    assert body["progress"] == 100
    assert body["commit_sha"] == SHA
    assert body["python_file_count"] == 2
    assert body["manifest_files"] == ["requirements.txt"]
    assert body["error"] is None

    with session_factory() as db:
        scan = db.get(Scan, scan_id)
        assert scan.workspace_path == f"/ws/scans/{scan_id}/repository"
        assert scan.repository_metadata["python_files"] == ["app.py", "utils.py"]


def test_fetch_failure_marks_scan_failed(client, session_factory, monkeypatch):
    scan_id = client.post("/api/scans", json={"repository_url": URL, "ref": "main"}).json()["scan_id"]

    def failing_fetch(*args):
        raise RepositoryFetchError("Could not access the repository. Make sure it exists and is public.")

    monkeypatch.setattr("app.worker.fetch_repository", failing_fetch)

    with session_factory() as db:
        process_scan(db, scan_service.claim_next_queued_scan(db))

    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["status"] == "failed"
    assert body["stage"] == "repository_fetch"
    assert body["error"] == "Could not access the repository. Make sure it exists and is public."
    assert body["commit_sha"] is None


def test_unexpected_crash_hides_details(client, session_factory, monkeypatch):
    scan_id = client.post("/api/scans", json={"repository_url": URL, "ref": "main"}).json()["scan_id"]

    def crash(*args):
        raise RuntimeError("secret internal detail /Users/x")

    monkeypatch.setattr("app.worker.fetch_repository", crash)

    with session_factory() as db:
        process_scan(db, scan_service.claim_next_queued_scan(db))

    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["status"] == "failed"
    assert "secret" not in body["error"]


def test_interrupted_scans_are_requeued(client, session_factory):
    scan_id = client.post("/api/scans", json={"repository_url": URL, "ref": "main"}).json()["scan_id"]
    with session_factory() as db:
        scan_service.claim_next_queued_scan(db)
        scan_service.requeue_interrupted_scans(db)

    body = client.get(f"/api/scans/{scan_id}").json()
    assert (body["status"], body["stage"], body["progress"]) == ("queued", "queued", 0)

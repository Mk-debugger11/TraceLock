import io
import zipfile
from pathlib import Path

from app.ingestion.github_loader import RepositoryFetchError, RepositoryMetadata
from app.models.scan import Scan
from app.services import scan_service
from app.worker import process_scan

URL = "https://github.com/owner/repo"
SHA = "c" * 40
BENCHMARK = Path(__file__).resolve().parents[2] / "benchmark"


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
    monkeypatch.setattr("app.worker.analyze_scan", lambda db, scan: None)  # fetch stage only

    with session_factory() as db:
        process_scan(db, scan_service.claim_next_queued_scan(db))

    assert calls == [(scan_id, URL, "main")]
    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["status"] == "ready_for_analysis"
    assert body["stage"] == "repository_fetched"
    assert body["progress"] == 50
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


def test_local_scan_copies_folder_into_workspace(client, session_factory, workspace, tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("import yaml\n")
    (project / "requirements.txt").write_text("pyyaml==5.3\n")
    monkeypatch.setenv("TRACELOCK_ALLOW_LOCAL_PATHS", "1")
    scan_id = client.post("/api/analyze", data={"repo_type": "local", "path": str(project)}).json()["scan_id"]

    with session_factory() as db:
        process_scan(db, scan_service.claim_next_queued_scan(db))

    body = client.get(f"/api/scans/{scan_id}").json()
    assert (body["status"], body["stage"]) == ("done", "analyzed")
    assert body["python_file_count"] == 1 and body["manifest_files"] == ["requirements.txt"]
    with session_factory() as db:
        assert db.get(Scan, scan_id).workspace_path == str(workspace / "scans" / scan_id / "repository")


def test_upload_scan_extracts_zip_and_deletes_it(client, session_factory, workspace):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("proj/app.py", "import yaml\n")
        zf.writestr("proj/requirements.txt", "pyyaml==5.3\n")
    res = client.post("/api/analyze", data={"repo_type": "upload"}, files={"repo_file": ("proj.zip", buf.getvalue())})
    scan_id = res.json()["scan_id"]

    with session_factory() as db:
        process_scan(db, scan_service.claim_next_queued_scan(db))

    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["status"] == "done"
    assert body["python_file_count"] == 1
    assert not (workspace / "uploads" / f"{scan_id}.zip").exists()
    with session_factory() as db:
        assert db.get(Scan, scan_id).workspace_path.endswith(f"{scan_id}/repository/proj")


def test_worker_analyzes_fixture_and_serves_results(client, session_factory, workspace, monkeypatch):
    monkeypatch.setenv("TRACELOCK_ALLOW_LOCAL_PATHS", "1")
    scan_id = client.post("/api/analyze", data={"repo_type": "local", "path": str(BENCHMARK / "three_hop_chain")}).json()["scan_id"]
    assert client.get(f"/api/scans/{scan_id}/result").status_code == 409  # not analysed yet

    with session_factory() as db:
        process_scan(db, scan_service.claim_next_queued_scan(db))

    body = client.get(f"/api/scans/{scan_id}").json()
    assert (body["status"], body["stage"], body["progress"], body["error"]) == ("done", "analyzed", 100, None)

    result = client.get(f"/api/scans/{scan_id}/result").json()
    pyyaml = [f for f in result["findings"] if f["dependency"]["name"] == "pyyaml"]
    assert pyyaml and any(f["verdict"] == "REACHABLE" for f in pyyaml)
    reachable = next(f for f in pyyaml if f["verdict"] == "REACHABLE")
    assert reachable["path"][0]["file"] == "app/main.py" and reachable["path"][-1]["qualname"] == "yaml.full_load"
    assert "raw" not in reachable["advisory"]

    vex = client.get(f"/api/scans/{scan_id}/result.vex.json")
    assert vex.status_code == 200 and "attachment" in vex.headers["content-disposition"]
    assert vex.json()["statements"][0]["status"] == "affected"
    sarif = client.get(f"/api/scans/{scan_id}/result.sarif")
    assert sarif.headers["content-type"].startswith("application/sarif+json")
    assert sarif.json()["runs"][0]["results"][0]["level"] == "error"


def test_analysis_failure_marks_scan_failed_without_paths(client, session_factory, workspace, tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("")
    monkeypatch.setenv("TRACELOCK_ALLOW_LOCAL_PATHS", "1")
    scan_id = client.post("/api/analyze", data={"repo_type": "local", "path": str(project)}).json()["scan_id"]
    seen = []

    def exploding_scan(root, offline):
        with session_factory() as db:
            scan = db.get(Scan, scan_id)
            seen.append((scan.status, scan.stage, scan.progress, offline))
        raise RuntimeError(f"cannot parse {root}/app.py\nmore detail")

    monkeypatch.setattr("app.worker.tracelock.scan", exploding_scan)

    with session_factory() as db:
        process_scan(db, scan_service.claim_next_queued_scan(db))

    assert seen == [("running", "analysis", 60, True)]
    body = client.get(f"/api/scans/{scan_id}").json()
    assert (body["status"], body["stage"]) == ("failed", "analysis")
    assert body["error"] == "Analysis failed: RuntimeError: cannot parse <project>/app.py"
    assert client.get(f"/api/scans/{scan_id}/result").json() == {"error": "Scan has no result yet (status: failed)"}


def test_result_endpoints_for_unknown_scan(client):
    for suffix in ("result", "result.vex.json", "result.sarif"):
        res = client.get(f"/api/scans/00000000-0000-0000-0000-000000000000/{suffix}")
        assert res.status_code == 404 and res.json() == {"error": "Scan not found"}


def test_interrupted_scans_are_requeued(client, session_factory):
    scan_id = client.post("/api/scans", json={"repository_url": URL, "ref": "main"}).json()["scan_id"]
    with session_factory() as db:
        scan_service.claim_next_queued_scan(db)
        scan_service.requeue_interrupted_scans(db)

    body = client.get(f"/api/scans/{scan_id}").json()
    assert (body["status"], body["stage"], body["progress"]) == ("queued", "queued", 0)

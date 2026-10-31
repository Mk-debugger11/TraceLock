"""Background worker: picks up queued scans, fetches their project and runs the TraceLock engine.

Run on its own with `python -m app.worker` (the API also starts it as a child process).
Run a single worker at a time. TRACELOCK_OFFLINE=1 keeps the engine off the network.
"""
import logging
import os
import time
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

import tracelock
from tracelock import report

from app.database.connection import SessionLocal, init_db
from app.ingestion.github_loader import RepositoryFetchError, RepositoryMetadata, fetch_repository
from app.ingestion.local_loader import fetch_local_directory, fetch_zip_archive, upload_path
from app.models.scan import SOURCE_LOCAL, SOURCE_UPLOAD, Scan
from app.services import scan_service

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 2
ANALYSIS_OFFLINE = os.environ.get("TRACELOCK_OFFLINE", "0") == "1"


def _fetch(scan: Scan) -> RepositoryMetadata:
    if scan.source_type == SOURCE_LOCAL:
        return fetch_local_directory(scan.id, scan.repository_url)
    if scan.source_type == SOURCE_UPLOAD:
        archive = upload_path(scan.id)
        try:
            return fetch_zip_archive(scan.id, archive, scan.repository_url)
        finally:
            archive.unlink(missing_ok=True)
    return fetch_repository(scan.id, scan.repository_url, scan.ref)


def process_scan(db: Session, scan: Scan) -> None:
    """Fetch the scan's project, analyse it and record the outcome. Never raises for a failed scan."""
    try:
        metadata = _fetch(scan)
    except RepositoryFetchError as exc:
        logger.warning("Scan %s failed: %s", scan.id, exc)
        scan_service.mark_scan_failed(db, scan, str(exc))
        return
    except Exception:
        logger.exception("Scan %s crashed", scan.id)
        scan_service.mark_scan_failed(db, scan, "Unexpected error while fetching the repository")
        return
    scan_service.mark_scan_fetched(db, scan, metadata.to_dict())
    logger.info("Scan %s fetched: %s @ %s", scan.id, metadata.repository_url, metadata.commit_sha)
    analyze_scan(db, scan)


def analyze_scan(db: Session, scan: Scan) -> None:
    """Run the engine on the fetched workspace and store its JSON. Never raises."""
    scan_service.mark_scan_analyzing(db, scan)
    workspace = Path(scan.workspace_path or "")
    try:
        if not scan.workspace_path or not workspace.is_dir():
            raise FileNotFoundError("the fetched workspace is missing")
        result = tracelock.scan(workspace, offline=ANALYSIS_OFFLINE)
        data = report.to_dict(result)
    except Exception as exc:
        logger.exception("Scan %s analysis failed", scan.id)
        scan_service.mark_scan_failed(db, scan, f"Analysis failed: {_short_error(exc, scan.workspace_path)}")
        return
    scan_service.mark_scan_done(db, scan, data)
    verdicts = [f["verdict"] for f in data["findings"]]
    logger.info("Scan %s done: %d findings, %d reachable", scan.id, len(verdicts), verdicts.count("REACHABLE"))


def _short_error(exc: Exception, workspace: Optional[str]) -> str:
    """One line for the user, without server paths."""
    text = (str(exc).splitlines() or [""])[0]
    if workspace:
        text = text.replace(workspace, "<project>")
    return f"{type(exc).__name__}: {text}"[:200] if text else type(exc).__name__


def run_worker() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    init_db()
    with SessionLocal() as db:
        scan_service.requeue_interrupted_scans(db)

    while True:
        try:
            with SessionLocal() as db:
                scan = scan_service.claim_next_queued_scan(db)
                if scan is not None:
                    process_scan(db, scan)
                    continue
        except Exception:
            logger.exception("Worker loop error")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_worker()

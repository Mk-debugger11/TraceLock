"""Background worker: picks up queued scans and fetches their repositories.

Run on its own with `python -m app.worker` (the API also starts it as a child process).
Run a single worker at a time.
"""
import logging
import time

from sqlalchemy.orm import Session

from app.database.connection import SessionLocal, init_db
from app.ingestion.github_loader import RepositoryFetchError, fetch_repository
from app.models.scan import Scan
from app.services import scan_service

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 2


def process_scan(db: Session, scan: Scan) -> None:
    """Fetch the scan's repository and record the outcome. Never raises for a failed scan."""
    try:
        metadata = fetch_repository(scan.id, scan.repository_url, scan.ref)
    except RepositoryFetchError as exc:
        logger.warning("Scan %s failed: %s", scan.id, exc)
        scan_service.mark_scan_failed(db, scan, str(exc))
        return
    except Exception:
        logger.exception("Scan %s crashed", scan.id)
        scan_service.mark_scan_failed(db, scan, "Unexpected error while fetching the repository")
        return
    scan_service.mark_scan_fetched(db, scan, metadata.to_dict())
    logger.info("Scan %s ready: %s @ %s", scan.id, metadata.repository_url, metadata.commit_sha)


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

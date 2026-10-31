from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.scan import (
    STAGE_ANALYSIS,
    STAGE_ANALYZED,
    STAGE_QUEUED,
    STAGE_REPOSITORY_FETCH,
    STAGE_REPOSITORY_FETCHED,
    SOURCE_GITHUB,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_QUEUED,
    STATUS_READY_FOR_ANALYSIS,
    STATUS_RUNNING,
    Scan,
)


def create_scan(
    db: Session,
    repository_url: str,
    ref: str,
    source_type: str = SOURCE_GITHUB,
    scan_id: Optional[str] = None,
) -> Scan:
    """Save a new queued scan. Cloning/analysis is left to a worker.

    Pass scan_id when files must be in place (an uploaded zip) before the worker can claim the scan.
    """
    scan = Scan(repository_url=repository_url, ref=ref, source_type=source_type)
    if scan_id is not None:
        scan.id = scan_id
    db.add(scan)
    db.commit()
    return scan


def get_scan(db: Session, scan_id: str) -> Optional[Scan]:
    return db.get(Scan, scan_id)


# --- State changes used by the worker ---------------------------------------


def claim_next_queued_scan(db: Session) -> Optional[Scan]:
    """Atomically move the oldest queued scan to running/repository_fetch and return it."""
    scan = db.scalars(
        select(Scan).where(Scan.status == STATUS_QUEUED).order_by(Scan.created_at).limit(1)
    ).first()
    if scan is None:
        return None
    claimed = db.execute(
        update(Scan)
        .where(Scan.id == scan.id, Scan.status == STATUS_QUEUED)
        .values(status=STATUS_RUNNING, stage=STAGE_REPOSITORY_FETCH, progress=15)
    )
    db.commit()
    if claimed.rowcount != 1:
        return None
    db.refresh(scan)
    return scan


def mark_scan_fetched(db: Session, scan: Scan, metadata: dict) -> None:
    scan.commit_sha = metadata["commit_sha"]
    scan.workspace_path = metadata["workspace_path"]
    scan.repository_metadata = metadata
    scan.status = STATUS_READY_FOR_ANALYSIS
    scan.stage = STAGE_REPOSITORY_FETCHED
    scan.progress = 50
    db.commit()


def mark_scan_analyzing(db: Session, scan: Scan) -> None:
    scan.status = STATUS_RUNNING
    scan.stage = STAGE_ANALYSIS
    scan.progress = 60
    db.commit()


def mark_scan_done(db: Session, scan: Scan, result: dict) -> None:
    scan.result = result
    scan.status = STATUS_DONE
    scan.stage = STAGE_ANALYZED
    scan.progress = 100
    db.commit()


def mark_scan_failed(db: Session, scan: Scan, message: str) -> None:
    scan.status = STATUS_FAILED
    scan.error_message = message
    db.commit()


def requeue_interrupted_scans(db: Session) -> None:
    """Scans still 'running' belong to a worker that died; queue them again."""
    db.execute(
        update(Scan)
        .where(Scan.status == STATUS_RUNNING)
        .values(status=STATUS_QUEUED, stage=STAGE_QUEUED, progress=0)
    )
    db.commit()

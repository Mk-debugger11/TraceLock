from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.schemas.scan import ScanCreateRequest, ScanCreateResponse, ScanStatusResponse
from app.services import scan_service

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
def create_scan(payload: ScanCreateRequest, db: Session = Depends(get_db)):
    scan = scan_service.create_scan(db, payload.repository_url, payload.ref)
    return ScanCreateResponse(
        scan_id=scan.id,
        status=scan.status,
        stage=scan.stage,
        progress=scan.progress,
        message="Repository scan queued successfully",
    )


@router.get("/{scan_id}", response_model=ScanStatusResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = scan_service.get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    metadata = scan.repository_metadata or {}
    return ScanStatusResponse(
        scan_id=scan.id,
        repository_url=scan.repository_url,
        ref=scan.ref,
        status=scan.status,
        stage=scan.stage,
        progress=scan.progress,
        error=scan.error_message,
        commit_sha=scan.commit_sha,
        python_file_count=metadata.get("python_file_count"),
        manifest_files=metadata.get("manifest_files"),
    )

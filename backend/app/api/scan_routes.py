from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from tracelock import report

from app.database.connection import get_db
from app.models.scan import STATUS_DONE, Scan
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
        source_type=scan.source_type,
        error=scan.error_message,
        commit_sha=scan.commit_sha,
        python_file_count=metadata.get("python_file_count"),
        manifest_files=metadata.get("manifest_files"),
    )


def _finished_scan(db: Session, scan_id: str) -> Scan:
    scan = scan_service.get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != STATUS_DONE or scan.result is None:
        raise HTTPException(status_code=409, detail=f"Scan has no result yet (status: {scan.status})")
    return scan


def _download(content: str, media_type: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/result")
def get_result(scan_id: str, db: Session = Depends(get_db)):
    """The engine's full JSON: tracelock.models.to_dict(ScanResult)."""
    return _finished_scan(db, scan_id).result


@router.get("/{scan_id}/result.vex.json")
def get_result_vex(scan_id: str, db: Session = Depends(get_db)):
    scan = _finished_scan(db, scan_id)
    return _download(report.to_openvex(report.from_dict(scan.result)), "application/json", f"tracelock-{scan.id}.vex.json")


@router.get("/{scan_id}/result.sarif")
def get_result_sarif(scan_id: str, db: Session = Depends(get_db)):
    scan = _finished_scan(db, scan_id)
    return _download(report.to_sarif(report.from_dict(scan.result)), "application/sarif+json", f"tracelock-{scan.id}.sarif")

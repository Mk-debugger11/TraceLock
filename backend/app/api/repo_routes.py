import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.ingestion.github_loader import RepositoryFetchError
from app.ingestion.local_loader import save_upload, upload_path
from app.models.scan import SOURCE_GITHUB, SOURCE_LOCAL, SOURCE_UPLOAD
from app.schemas.scan import ScanCreateResponse, normalize_repository_url, validate_ref
from app.services import repo_service, scan_service

router = APIRouter(prefix="/api", tags=["repository"])


def local_paths_allowed() -> bool:
    # Off by default: a local scan copies any folder the server can read into the workspace.
    return os.environ.get("TRACELOCK_ALLOW_LOCAL_PATHS", "0") == "1"


class BranchesRequest(BaseModel):
    repo_url: str


@router.post("/branches")
def get_branches(payload: BranchesRequest):
    try:
        return {"branches": repo_service.list_branches(payload.repo_url)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc))


@router.post("/analyze", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
def analyze(
    repo_type: str = Form(...),
    repo_url: Optional[str] = Form(None),
    branch: Optional[str] = Form(None),
    path: Optional[str] = Form(None),
    scan_mode: str = Form("full"),
    repo_file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    """Queue a scan from the web form: a GitHub repo, an uploaded zip, or (when enabled) a local folder."""
    if repo_type == SOURCE_GITHUB:
        try:
            url = normalize_repository_url(repo_url or "")
            ref = validate_ref(branch or "")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        scan = scan_service.create_scan(db, url, ref)
    elif repo_type == SOURCE_UPLOAD:
        if repo_file is None:
            raise HTTPException(status_code=422, detail="repo_file is required")
        scan_id = str(uuid.uuid4())
        try:
            save_upload(repo_file.file, upload_path(scan_id))  # before the row exists, so the worker never waits
        except RepositoryFetchError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        name = Path(repo_file.filename or "upload.zip").name[:255]
        scan = scan_service.create_scan(db, name, "", source_type=SOURCE_UPLOAD, scan_id=scan_id)
    elif repo_type == SOURCE_LOCAL:
        if not local_paths_allowed():
            raise HTTPException(status_code=403, detail="Local folder scans are disabled (set TRACELOCK_ALLOW_LOCAL_PATHS=1)")
        local = Path(path or "").expanduser()
        if not path or not local.is_absolute() or not local.is_dir():
            raise HTTPException(status_code=400, detail="path must be an absolute path to a directory")
        scan = scan_service.create_scan(db, str(local.resolve()), "", source_type=SOURCE_LOCAL)
    else:
        raise HTTPException(status_code=422, detail="repo_type must be github, upload or local")

    return ScanCreateResponse(
        scan_id=scan.id,
        status=scan.status,
        stage=scan.stage,
        progress=scan.progress,
        message="Scan queued successfully",
    )

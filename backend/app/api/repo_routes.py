from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from app.services import repo_service

router = APIRouter(prefix="/api", tags=["repository"])


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


@router.post("/analyze")
def analyze(
    repo_type: Optional[str] = Form(None),
    repo_url: Optional[str] = Form(None),
    branch: Optional[str] = Form(None),
    scan_mode: str = Form("full"),
    repo_file: Optional[UploadFile] = File(None),
):
    # Placeholder the frontend currently calls; real scans go through POST /api/scans.
    return {
        "status": "success",
        "message": "Repository received for full analysis",
        "received_data": {
            "repo_type": repo_type,
            "repo_url": repo_url,
            "uploaded_file": repo_file.filename if repo_file else None,
            "branch": branch,
            "scan_mode": scan_mode,
        },
    }

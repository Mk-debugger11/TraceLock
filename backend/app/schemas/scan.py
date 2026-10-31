import re
from typing import List, Optional

from pydantic import BaseModel, field_validator

# https://github.com/<owner>/<repo>, optionally with www., a trailing ".git" or "/".
_URL_RE = re.compile(
    r"https://(?:www\.)?github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?"
)
# Branch names and commit SHAs: a safe subset of what git allows.
_REF_RE = re.compile(r"[A-Za-z0-9._/-]{1,255}")


def normalize_repository_url(value: str) -> str:
    """Return https://github.com/owner/repo, or raise ValueError if it isn't a GitHub repo URL."""
    match = _URL_RE.fullmatch(value.strip())
    if not match or match[2] in (".", ".."):
        raise ValueError("must be a GitHub repository URL like https://github.com/owner/repository")
    return f"https://github.com/{match[1]}/{match[2]}"


def validate_ref(value: str) -> str:
    """Return the stripped branch name or commit SHA, or raise ValueError."""
    value = value.strip()
    if not value:
        raise ValueError("must not be blank")
    if (
        not _REF_RE.fullmatch(value)
        or value.startswith(("-", "/", "."))
        or value.endswith(("/", ".", ".lock"))
        or ".." in value
    ):
        raise ValueError("must be a valid branch name or commit SHA")
    return value


class ScanCreateRequest(BaseModel):
    repository_url: str
    ref: str

    @field_validator("repository_url")
    @classmethod
    def validate_repository_url(cls, value: str) -> str:
        return normalize_repository_url(value)

    @field_validator("ref")
    @classmethod
    def validate_ref_field(cls, value: str) -> str:
        return validate_ref(value)


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str
    stage: str
    progress: int
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    repository_url: str
    ref: str
    status: str
    stage: str
    progress: int
    source_type: str = "github"
    error: Optional[str] = None
    # Filled in once the repository has been fetched.
    commit_sha: Optional[str] = None
    python_file_count: Optional[int] = None
    manifest_files: Optional[List[str]] = None

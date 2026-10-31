import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


# Scan lifecycle: queued -> running (repository_fetch) -> ready_for_analysis (repository_fetched), or failed.
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_READY_FOR_ANALYSIS = "ready_for_analysis"
STATUS_FAILED = "failed"

STAGE_QUEUED = "queued"
STAGE_REPOSITORY_FETCH = "repository_fetch"
STAGE_REPOSITORY_FETCHED = "repository_fetched"

# Where the project comes from. For local and upload scans repository_url holds the path or file name.
SOURCE_GITHUB = "github"
SOURCE_LOCAL = "local"
SOURCE_UPLOAD = "upload"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source_type: Mapped[str] = mapped_column(String(16), default=SOURCE_GITHUB)
    repository_url: Mapped[str] = mapped_column(String(512))
    ref: Mapped[str] = mapped_column(String(255))
    commit_sha: Mapped[Optional[str]] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default=STATUS_QUEUED)
    stage: Mapped[str] = mapped_column(String(32), default=STAGE_QUEUED)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    workspace_path: Mapped[Optional[str]] = mapped_column(String(1024))
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    # Output of the repository fetcher (python_files, manifest_files, ...) for the next pipeline stage.
    repository_metadata: Mapped[Optional[dict]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

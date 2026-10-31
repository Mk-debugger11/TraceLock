import os
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

_DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "tracelock.db"
DATABASE_URL = os.environ.get("TRACELOCK_DATABASE_URL", f"sqlite:///{_DEFAULT_DB_PATH}")


class Base(DeclarativeBase):
    pass


# check_same_thread=False: FastAPI runs sync endpoints in a threadpool, and each
# request gets its own session, so sharing the SQLite connection pool is safe.
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create tables if they don't exist yet."""
    # Imported here so every model is registered on Base before create_all.
    from app.models import scan  # noqa: F401

    Base.metadata.create_all(bind=engine)

    # create_all never alters existing tables, so add columns introduced after the first release.
    columns = {col["name"] for col in inspect(engine).get_columns("scans")}
    if "repository_metadata" not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE scans ADD COLUMN repository_metadata JSON"))
    if "source_type" not in columns:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE scans ADD COLUMN source_type VARCHAR(16) NOT NULL DEFAULT 'github'"))


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding one session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

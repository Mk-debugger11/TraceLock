from functools import partial

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.connection import Base, get_db
from app.ingestion import local_loader
from app.main import app
from app.models import scan  # noqa: F401  (registers the Scan table)


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    """Point the API and worker at a temporary workspace instead of the real one."""
    root = tmp_path / "workspace"
    monkeypatch.setattr("app.api.repo_routes.upload_path", partial(local_loader.upload_path, workspace_root=root))
    monkeypatch.setattr("app.worker.upload_path", partial(local_loader.upload_path, workspace_root=root))
    monkeypatch.setattr(
        "app.worker.fetch_local_directory", partial(local_loader.fetch_local_directory, workspace_root=root)
    )
    monkeypatch.setattr("app.worker.fetch_zip_archive", partial(local_loader.fetch_zip_archive, workspace_root=root))
    return root


@pytest.fixture()
def session_factory():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    yield sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    engine.dispose()


@pytest.fixture()
def client(session_factory):
    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    # No `with` block: skips the lifespan so tests never touch the real tracelock.db.
    yield TestClient(app)
    app.dependency_overrides.clear()

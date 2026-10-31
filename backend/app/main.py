import logging
import multiprocessing
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api import repo_routes, scan_routes
from app.database.connection import init_db
from app.worker import run_worker

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    # The worker is a separate process, so cloning never runs inside the API.
    # Set TRACELOCK_RUN_WORKER=0 to run it yourself with `python -m app.worker`.
    worker = None
    if os.environ.get("TRACELOCK_RUN_WORKER", "1") != "0":
        worker = multiprocessing.Process(target=run_worker, name="tracelock-worker", daemon=True)
        worker.start()
    yield
    if worker is not None:
        worker.terminate()
        worker.join(timeout=5)


app = FastAPI(title="TraceLock API", lifespan=lifespan)

# Vite dev server (port 3000), so the React frontend can call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(scan_routes.router)
app.include_router(repo_routes.router)


# All errors look like {"error": "..."}, which is what the frontend reads.
@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    problems = []
    for err in exc.errors():
        field = ".".join(str(part) for part in err["loc"][1:]) or "body"
        message = "is required" if err["type"] == "missing" else err["msg"].removeprefix("Value error, ")
        problems.append(f"{field} {message}")
    return JSONResponse(status_code=422, content={"error": "; ".join(problems)})


@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


@app.exception_handler(SQLAlchemyError)
async def database_error(_: Request, exc: SQLAlchemyError):
    logger.exception("Database error", exc_info=exc)
    return JSONResponse(status_code=500, content={"error": "Database error, please try again later"})

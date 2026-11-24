"""boxcutter server: the web UI (SPA + its /api endpoints, behind HTTP basic auth), the scanner-agent protocol
(/runner/*, token auth) and the background sweeper.

There is deliberately no public REST API: no OpenAPI docs, no API keys, no CORS. /api exists only for the
bundled UI.

Run: uvicorn app.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI
from sqlmodel import Session

from .activity import cap_job_events, prune_logs
from .config import settings
from .db import engine, init_db
from .queue import reconcile_drained_scans, requeue_stale, run_due_schedulers
from .routers import fleet, runners, scans, schedulers, templates
from .routers import settings as settings_router
from .security import BasicAuthMiddleware
from .seed import seed


async def _sweeper() -> None:
    cycle = 0
    while True:
        try:
            with Session(engine) as s:
                requeue_stale(s)
                reconcile_drained_scans(s)
                run_due_schedulers(s)
                cycle += 1
                if cycle % 20 == 0:      # ~ every 10 min: trim old log rows + cap each job's live log
                    prune_logs(s, settings.activity_retention_days)
                    cap_job_events(s, settings.log_max_events_per_job)
        except Exception:  # noqa: BLE001 - the sweeper must never die
            pass
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed()
    task = asyncio.create_task(_sweeper())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="boxcutter", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.add_middleware(BasicAuthMiddleware)


@app.get("/health")
def health():
    return {"ok": True}


app.include_router(runners.router)

api = APIRouter(prefix="/api")
for r in (scans.router, templates.router, schedulers.router, settings_router.router, fleet.router):
    api.include_router(r)
app.include_router(api)

# the built SPA (web/dist is copied to ./web_dist in the image)
_web = Path(__file__).resolve().parent.parent / "web_dist"
if _web.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(_web), html=True), name="web")

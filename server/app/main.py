"""boxcutter-ui server entrypoint: create tables, seed root/root, run the stale-job sweeper, mount routers.

Run: uvicorn app.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import PlainTextResponse
from sqlmodel import Session

from .activity import cap_job_events, prune_logs
from .config import settings
from .db import engine, init_db
from .queue import requeue_stale
from .routers import admin, auth, keys, ollama, runners, scans, templates
from .seed import seed


async def _sweeper() -> None:
    cycle = 0
    while True:
        try:
            with Session(engine) as s:
                requeue_stale(s)
                cycle += 1
                if cycle % 20 == 0:      # ~ every 10 min: trim log rows past retention + cap each job's live log
                    prune_logs(s, settings.activity_retention_days)
                    cap_job_events(s, settings.log_max_events_per_job)
        except Exception:  # noqa: BLE001 - the sweeper must never die
            pass
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed()
    tasks = [asyncio.create_task(_sweeper())]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()


_API_DESCRIPTION = """
The **boxcutter-ui** REST API. Authenticate one of two ways:

* **JWT** — `POST /auth/login` with a username/password, then send `Authorization: Bearer <token>`.
* **API key** — create one under Settings → API keys (or a system user), then send it as `X-API-Key: <key>`
  or `Authorization: Bearer <key>`.

Click **Authorize** below to try the endpoints. Interactive docs at `/docs`, ReDoc at `/redoc`,
raw schema at `/openapi.json`.
"""

_OPENAPI_TAGS = [
    {"name": "auth", "description": "Login, current user, change password."},
    {"name": "scans", "description": "Create/list scans, findings, live log (SSE), per-target debug, report."},
    {"name": "templates", "description": "Scan templates: workflow / tool / ai_agent."},
    {"name": "runners", "description": "Scanner (runner) enrollment, job claim/result/heartbeat, fleet."},
    {"name": "admin", "description": "Users and LLM profiles (admin)."},
    {"name": "keys", "description": "Personal API keys and system (API-only) users."},
]

app = FastAPI(title="boxcutter-ui", version="0.1.0", description=_API_DESCRIPTION,
              openapi_tags=_OPENAPI_TAGS, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])


def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(title=app.title, version=app.version, description=_API_DESCRIPTION,
                         tags=_OPENAPI_TAGS, routes=app.routes)
    comps = schema.setdefault("components", {}).setdefault("securitySchemes", {})
    comps["bearerAuth"] = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT",
                           "description": "A user JWT, or an API key (bck_...)."}
    comps["apiKey"] = {"type": "apiKey", "in": "header", "name": "X-API-Key",
                       "description": "A personal or system-user API key."}
    schema["security"] = [{"bearerAuth": []}, {"apiKey": []}]   # Authorize works for both
    app.openapi_schema = schema
    return schema


app.openapi = _custom_openapi


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/runner.py", response_class=PlainTextResponse)
def runner_bootstrap():
    """Serve the runner supervisor so a stock-image container can self-bootstrap:
    docker run ... --entrypoint python3 ghcr.io/zzzteph/boxcutter -c "exec(urlopen('SERVER/runner.py').read())"
    """
    path = os.environ.get("RUNNER_BOOTSTRAP_PATH", "/app/runner/supervisor.py")
    p = Path(path)
    if p.exists():
        return p.read_text(encoding="utf-8")
    return "# runner supervisor not bundled on the server; mount runner/ or set RUNNER_BOOTSTRAP_PATH\n"


app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(runners.router)
app.include_router(templates.router)
app.include_router(admin.router)
app.include_router(keys.router)
app.include_router(ollama.router)

# Prod: serve the built SPA if present (web/dist copied to ./web_dist in the image).
_web = Path(__file__).resolve().parent.parent / "web_dist"
if _web.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(_web), html=True), name="web")

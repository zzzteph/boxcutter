"""Settings. Every value has a working default, so the server runs with `docker run` and no env file at all;
set any as an environment variable to override (an optional .env is also read if present)."""
from __future__ import annotations

import os
import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict

# The literal default below. When SECRET_KEY is left unset we swap this for a random secret persisted to the
# data dir (see resolve_persisted_secret) — so tokens survive restarts and every deployment is unique, with
# zero configuration.
DEV_SECRET = "dev-secret-change-me-in-production-0123456789"


def resolve_persisted_secret(database_url: str) -> str:
    """Load (or create once) a random JWT secret next to the data dir. Keeps one-command deploys
    secure-by-default and stable across restarts. For multiple server replicas, set SECRET_KEY explicitly."""
    if database_url.startswith("sqlite"):
        path = database_url.split("///", 1)[-1] if "///" in database_url else "./data/db"
        d = os.path.dirname(path) or "."
    else:
        d = os.environ.get("DATA_DIR", "data")
    try:
        os.makedirs(d, exist_ok=True)
        f = os.path.join(d, "secret.key")
        if os.path.exists(f):
            existing = open(f, encoding="utf-8").read().strip()
            if existing:
                return existing
        value = secrets.token_urlsafe(48)
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(value)
        try:
            os.chmod(f, 0o600)
        except Exception:
            pass
        return value
    except Exception:
        return secrets.token_urlsafe(48)   # ephemeral fallback (sessions reset on restart)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: str = DEV_SECRET   # >=32 bytes keeps pyjwt happy; auto-persisted when left unset
    database_url: str = "sqlite:///./data/boxcutter_ui.db"
    jwt_expire_minutes: int = 720

    admin_user: str = "root"
    admin_password: str = "root"

    boxcutter_image: str = "ghcr.io/zzzteph/boxcutter:latest"
    job_visibility_timeout: int = 180        # seconds without a heartbeat before a claimed job is requeued
    job_max_attempts: int = 3                # a job is retried up to this many times before it's marked failed
    activity_retention_days: int = 30        # prune activity + job-event log rows older than this (0 = keep all)
    log_max_events_per_job: int = 1000       # keep only the newest N live-log events per job (0 = unlimited)
    enroll_token: str = ""                   # empty = none seeded; create one in the UI (Scanners → enroll token)

    # optional notifications (scan-done, new-critical); all empty = disabled
    notify_webhook: str = ""                 # any URL that accepts a JSON POST
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""


settings = Settings()

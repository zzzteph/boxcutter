"""Settings. Every value has a working default, so the server runs with `docker run` and no env file at all;
set any as an environment variable to override (an optional .env is also read if present)."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/boxcutter.db"

    # HTTP basic auth: one account. The username is fixed; the password starts as ADMIN_PASSWORD on first boot
    # and is changed from Settings in the UI (stored hashed in the DB from then on).
    admin_user: str = "admin"
    admin_password: str = "admin"

    job_visibility_timeout: int = 180        # seconds without a heartbeat before a claimed job is requeued
    job_max_attempts: int = 3                # a job is retried up to this many times before it's marked failed
    activity_retention_days: int = 30        # prune activity + job-event log rows older than this (0 = keep all)
    log_max_events_per_job: int = 1000       # keep only the newest N live-log events per job (0 = unlimited)
    enroll_token: str = ""                   # empty = none seeded; create one in the UI (Scanners -> enroll token)

    # optional first-boot seed for the notification settings (editable in the UI afterwards)
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    slack_webhook_url: str = ""


settings = Settings()

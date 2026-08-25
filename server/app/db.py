"""Engine + session. SQLite (WAL) by default; set DATABASE_URL to a postgresql+psycopg:// URL for Postgres.

The DB is also the job queue - see app/queue.py for the atomic claim."""
from __future__ import annotations

import os

from sqlmodel import Session, SQLModel, create_engine

from .config import DEV_SECRET, resolve_persisted_secret, settings

_is_sqlite = settings.database_url.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}
engine = create_engine(settings.database_url, echo=False, pool_pre_ping=True, connect_args=_connect_args)


# Additive, best-effort migrations so a new release that introduces a column does not require dropping the DB
# (SQLite can't add a column via create_all, and a manual reset loses data). Only ADD COLUMN — never
# destructive — and it is a no-op once the column exists. (table, column, sql_type, default_literal).
_ADDED_COLUMNS = [
    ("scan", "vars_json", "TEXT", "'{}'"),
    ("runner", "ip", "VARCHAR(64)", "''"),
    ("runner", "desired_slots", "INTEGER", "NULL"),
    ("user", "totp_secret", "TEXT", "NULL"),
    ("user", "totp_enabled", "BOOLEAN", "0"),
    ("template", "description", "TEXT", "''"),
    ("job", "token", "VARCHAR(32)", "''"),
    ("runner", "internal", "BOOLEAN", "0"),
    ("runner", "engine_version", "VARCHAR(64)", "''"),
    ("job", "needs_model", "VARCHAR(120)", "''"),
]


def _ensure_columns() -> None:
    from sqlalchemy import inspect
    insp = inspect(engine)
    prep = engine.dialect.identifier_preparer     # quotes reserved names ("user") correctly per dialect
    try:
        tables = set(insp.get_table_names())
    except Exception:
        return
    with engine.begin() as conn:
        for table, column, sqltype, default in _ADDED_COLUMNS:
            if table not in tables:
                continue
            try:
                cols = {c["name"] for c in insp.get_columns(table)}
            except Exception:
                continue
            if column in cols:
                continue
            try:
                conn.exec_driver_sql(
                    f"ALTER TABLE {prep.quote(table)} ADD COLUMN {prep.quote(column)} {sqltype} DEFAULT {default}")
            except Exception:
                pass


# Indexes that speed the hot paths at scale (fresh DBs get them from the models; this adds them to a DB that
# predates the column/index). Best-effort CREATE INDEX — skipped if already present. (name, table, columns).
_ADDED_INDEXES = [
    ("ix_job_status", "job", "(status)"),
    ("ix_job_scan_status_created", "job", "(scan_id, status, created_at)"),
    ("ix_scan_status", "scan", "(status)"),
    ("ix_finding_scan_fp", "finding", "(scan_id, fingerprint)"),
    ("ix_finding_scan_sev", "finding", "(scan_id, severity)"),
    ("ix_jobevent_at", "jobevent", "(at)"),
]


def _ensure_indexes() -> None:
    from sqlalchemy import inspect
    insp = inspect(engine)
    try:
        tables = set(insp.get_table_names())
    except Exception:
        return
    with engine.begin() as conn:
        for name, table, cols in _ADDED_INDEXES:
            if table not in tables:
                continue
            try:
                if name in {ix.get("name") for ix in insp.get_indexes(table)}:
                    continue
            except Exception:
                pass
            try:
                conn.exec_driver_sql(f"CREATE INDEX {name} ON {table} {cols}")
            except Exception:
                pass


def init_db() -> None:
    # secure-by-default: if SECRET_KEY wasn't provided, use a random secret persisted to the data dir
    if settings.secret_key == DEV_SECRET:
        settings.secret_key = resolve_persisted_secret(settings.database_url)
    if _is_sqlite:
        os.makedirs("data", exist_ok=True)
    # import models so metadata is populated before create_all
    from . import models  # noqa: F401
    SQLModel.metadata.create_all(engine)
    _ensure_columns()
    _ensure_indexes()
    if _is_sqlite:
        with engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA busy_timeout=5000")


def get_session():
    with Session(engine) as session:
        yield session

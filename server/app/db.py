"""Engine + session. SQLite (WAL) by default; set DATABASE_URL to a postgresql+psycopg:// URL for Postgres.

The DB is also the job queue - see app/queue.py for the atomic claim."""
from __future__ import annotations

import os

from sqlmodel import Session, SQLModel, create_engine

from .config import settings

_is_sqlite = settings.database_url.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}
engine = create_engine(settings.database_url, echo=False, pool_pre_ping=True, connect_args=_connect_args)


def init_db() -> None:
    if _is_sqlite:
        path = settings.database_url.split("///", 1)[-1]
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
    from . import models  # noqa: F401 - populate the metadata before create_all
    assert models
    SQLModel.metadata.create_all(engine)
    if _is_sqlite:
        with engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA busy_timeout=5000")


def get_session():
    with Session(engine) as session:
        yield session

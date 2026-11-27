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
    _add_missing_columns()
    if _is_sqlite:
        with engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA busy_timeout=5000")


def _add_missing_columns() -> None:
    """Tiny forward-only migration: add columns a newer version introduced to tables an older one created
    (create_all never alters an existing table). New columns are nullable or carry a default."""
    from sqlalchemy import inspect, text
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in SQLModel.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                ddl = col.type.compile(dialect=engine.dialect)
                default = col.default.arg if col.default is not None and not callable(col.default.arg) else None
                if isinstance(default, bool):
                    default = int(default)
                clause = ""
                if isinstance(default, (int, float)):
                    clause = f" DEFAULT {default}"
                elif isinstance(default, str) and ddl.upper().startswith(("VARCHAR", "CHAR")):
                    clause = " DEFAULT '" + default.replace("'", "''") + "'"
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ddl}{clause}'))


def get_session():
    with Session(engine) as session:
        yield session

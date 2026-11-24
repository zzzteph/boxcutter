"""SQLModel tables.

Every string column has an explicit VARCHAR length or is TEXT, so CREATE TABLE compiles on MySQL/MariaDB (it
would otherwise reject an unbounded VARCHAR). Lengths are also fine on SQLite/Postgres. Long/free-form fields
(JSON blobs, evidence, output, log lines) use TEXT; short identifiers and anything indexed use VARCHAR."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, Index, Text
from sqlmodel import Field, SQLModel


def now() -> datetime:
    return datetime.now(timezone.utc)


def _text(default=""):
    """A TEXT column with a python-side default (for long/free-form values)."""
    return Field(default=default, sa_column=Column(Text))


class AppSettings(SQLModel, table=True):
    """Singleton (id=1). The one admin account's password hash (HTTP basic auth; the username is fixed)."""
    id: Optional[int] = Field(default=1, primary_key=True)
    admin_password_hash: str = Field(default="", max_length=255)
    password_changed_at: Optional[datetime] = None


class Template(SQLModel, table=True):
    """A scan type the UI can run.

    kind:
      tool      - one engine tool (`boxcutter <tool> <target>`), one job per target
      workflow  - one engine YAML workflow (`boxcutter workflow <name> <target>`), one job per target
      pipeline  - a chain of the above: each stage's results are filtered by data type and fanned out as
                  separate jobs to the next stage, spread across every scanner. Built-in pipelines are the
                  distributed versions of the composite workflows; users build their own.
    spec_json:
      tool/workflow -> {"name": "<engine name>", "params": [{"flag": "--x", "value": "y"}]}
      pipeline      -> {"stages": [{"template_id": 1, "from": [-1], "input": "urls", "args": ""}, ...]}
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True, max_length=120)   # slug
    title: str = Field(default="", max_length=200)               # human name shown in the UI
    kind: str = Field(max_length=16)
    builtin: bool = False
    variant_of: str = Field(default="", max_length=120)          # built-in pipeline: the workflow it distributes
    category: str = Field(default="Custom", max_length=40)
    accepts: str = Field(default="any", max_length=24)           # domain|host|url|endpoint|js|spec|graphql|network|any
    produces: str = Field(default="findings", max_length=16)     # findings|hosts|urls|items
    depth: str = Field(default="standard", max_length=16)        # quick|standard|deep
    description: str = _text("")
    spec_json: str = _text("{}")
    created_at: datetime = Field(default_factory=now)


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=255)
    template_id: Optional[int] = Field(default=None, index=True)
    template_name: str = Field(default="", max_length=200)       # denormalized, survives a template delete
    scheduler_id: Optional[int] = Field(default=None, index=True)
    status: str = Field(default="queued", index=True, max_length=24)   # queued|running|paused|stopped|done
    run_no: int = 0
    vars_json: str = _text("{}")                                 # {custom: [{key, value}], debug: bool}
    plan_json: str = _text("[]")                                 # the stage plan of the current run (snapshot)
    created_at: datetime = Field(default_factory=now)
    last_run_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class Target(SQLModel, table=True):
    """What a job runs on. stage = -1 for the scan's own (user-supplied) targets; stage = i for the items that
    were fanned out into pipeline stage i. `key` de-duplicates within a stage; `args_json` carries per-target
    extra argv (e.g. --method/--data for a captured POST request)."""
    __table_args__ = (Index("ix_target_scan_stage_key", "scan_id", "stage", "key"),)
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(index=True)
    stage: int = Field(default=-1)
    value: str = Field(max_length=1024)
    key: str = Field(default="", max_length=64)
    args_json: str = _text("")


class Job(SQLModel, table=True):
    __table_args__ = (Index("ix_job_scan_status_created", "scan_id", "status", "created_at"),
                      Index("ix_job_scan_run_stage", "scan_id", "run_no", "stage", "status"))
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(index=True)
    target_id: int = Field(index=True)
    run_no: int = 0
    stage: int = 0                                               # index into the scan's plan
    dedup_key: str = Field(index=True, unique=True, max_length=64)
    # opaque per-job run token: integer PKs get reused after a scan is deleted (SQLite reuses rowids), so a
    # stale agent finishing a deleted job could post its result to a REUSED id now owned by a new scan. The
    # agent echoes this token; result/event posts whose token doesn't match the current job are rejected.
    token: str = Field(default="", max_length=32)
    status: str = Field(default="pending", index=True, max_length=24)  # pending|claimed|running|done|failed|cancelled
    runner_id: Optional[int] = Field(default=None, index=True)
    attempts: int = 0
    argv_json: str = _text("[]")                                # the exact boxcutter command run for this target
    output: str = _text("")                                     # raw engine stdout for the debug view
    claimed_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=now)


class Finding(SQLModel, table=True):
    __table_args__ = (Index("ix_finding_scan_fp", "scan_id", "fingerprint"),
                      Index("ix_finding_scan_sev", "scan_id", "severity"))
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(index=True)
    target: str = Field(default="", max_length=1024)
    fingerprint: str = Field(index=True, max_length=128)
    template_kind: str = Field(default="", max_length=32)
    severity: str = Field(default="info", max_length=24)
    title: str = Field(default="", max_length=400)
    url: str = Field(default="", max_length=2048)
    cls: str = Field(default="", max_length=120)
    evidence: str = _text("")
    reproduce: str = _text("")
    state: str = Field(default="new", max_length=24)             # new | open | resolved  (auto, from the diff)
    first_seen: datetime = Field(default_factory=now)
    last_seen: datetime = Field(default_factory=now)
    raw_json: str = _text("{}")


class ScanItem(SQLModel, table=True):
    """A non-finding result: a URL, host or endpoint a tool/workflow emits instead of an issue. Listable and
    downloadable one-per-line; in a pipeline these are what flows into the next stage."""
    __table_args__ = (Index("ix_scanitem_scan_fp", "scan_id", "fingerprint"),
                      Index("ix_scanitem_scan_type", "scan_id", "asset_type"))
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(index=True)
    target: str = Field(default="", max_length=1024)
    template_kind: str = Field(default="", max_length=32)
    fingerprint: str = Field(default="", max_length=128)
    value: str = Field(default="", max_length=2048)
    asset_type: str = Field(default="", max_length=16)           # domain|subdomain|url|ip|endpoint|other
    label: str = Field(default="", max_length=400)
    cls: str = Field(default="", max_length=120)
    stage: int = 0
    run_no: int = 0
    first_seen: datetime = Field(default_factory=now)
    last_seen: datetime = Field(default_factory=now)


class Scheduler(SQLModel, table=True):
    """A recurring scan: a name, how often, what to run and on what. It owns one Scan and re-runs it every
    `interval_seconds`, so the findings diff over time (new / open / resolved)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=200)
    template_id: int = Field(index=True)
    targets_text: str = _text("")                               # one target per line
    vars_json: str = _text("{}")
    interval_seconds: int = 86400
    enabled: bool = True
    scan_id: Optional[int] = Field(default=None, index=True)
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=now)


class JobEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: int = Field(index=True)
    scan_id: int = Field(index=True)
    phase: str = Field(default="", max_length=64)
    agent: str = Field(default="", max_length=64)
    line: str = _text("")
    at: datetime = Field(default_factory=now, index=True)        # indexed for age-based log retention pruning


class Runner(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(default="", max_length=150)
    host: str = Field(default="", max_length=255)
    internal: bool = False                                       # the server's built-in agent (not removable)
    ip: str = Field(default="", max_length=64)
    version: str = Field(default="", max_length=40)
    engine_version: str = Field(default="", max_length=64)
    status: str = Field(default="idle", max_length=24)           # idle | busy | disconnected (from last_heartbeat)
    slots: int = 1                                               # concurrency the agent currently reports
    desired_slots: Optional[int] = None                          # concurrency the server asks the agent to adopt
    busy_slots: int = 0
    current_jobs_json: str = _text("[]")
    metrics_json: str = _text("{}")                              # {"cpu": pct, "mem": pct}
    token_hash: str = Field(default="", max_length=128, index=True)
    last_heartbeat: Optional[datetime] = None
    enrolled_at: datetime = Field(default_factory=now)


class Activity(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=now, index=True)
    kind: str = Field(default="", max_length=40)                 # scan_created | job_claimed | scan_done | ...
    message: str = Field(default="", max_length=500)
    scan_id: Optional[int] = Field(default=None, index=True)
    runner_id: Optional[int] = Field(default=None)
    severity: str = Field(default="info", max_length=16)         # info | warn | critical


class NotifySettings(SQLModel, table=True):
    """Singleton (id=1): Telegram + Slack notifications. Bot token / webhook URL are server-only secrets."""
    id: Optional[int] = Field(default=1, primary_key=True)
    telegram_enabled: bool = False
    telegram_token: str = _text("")
    telegram_chat_id: str = Field(default="", max_length=64)
    slack_enabled: bool = False
    slack_webhook: str = _text("")
    severities_json: str = _text('["Critical", "High"]')        # which new-finding severities to send
    scan_done: bool = True                                       # also send a summary when a scan finishes


class EnrollToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token_hash: str = Field(index=True, max_length=128)
    label: str = Field(default="", max_length=150)
    prefix: str = Field(default="", max_length=16)
    created_at: datetime = Field(default_factory=now)
    revoked: bool = False

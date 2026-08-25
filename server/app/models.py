"""SQLModel tables. See SPEC.md section 4.

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


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, max_length=150)
    password_hash: str = Field(max_length=255)
    role: str = Field(default="user", max_length=32)          # admin | user | service
    must_change_password: bool = False
    totp_secret: Optional[str] = Field(default=None, sa_column=Column(Text))   # base32 TOTP secret, server-only
    totp_enabled: bool = False                                # optional per-user 2FA
    created_at: datetime = Field(default_factory=now)


class ApiKey(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    name: str = Field(default="", max_length=120)
    prefix: str = Field(default="", max_length=32)
    key_hash: str = Field(index=True, max_length=128)
    created_at: datetime = Field(default_factory=now)
    last_used_at: Optional[datetime] = None
    revoked: bool = False


class LLMProfile(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True, max_length=150)
    provider: str = Field(max_length=40)                      # anthropic | openai | litellm
    model: Optional[str] = Field(default=None, max_length=120)
    proxy_url: Optional[str] = Field(default=None, max_length=500)
    api_key_secret: str = _text("")                          # server-only, never serialized to the browser
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")


class Template(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=200)
    kind: str = Field(max_length=32)                          # workflow | tool | ai_agent
    spec_json: str = _text("{}")                             # {"name": "...", "flags": [...]}
    description: str = _text("")                             # official boxcutter description, shown in the picker
    context: Optional[str] = Field(default=None, sa_column=Column(Text))
    llm_profile_id: Optional[int] = Field(default=None, foreign_key="llmprofile.id")
    owner_id: int = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=now)


class TemplateShare(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    template_id: int = Field(foreign_key="template.id", index=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    perm: str = Field(default="read", max_length=16)


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=255)
    owner_id: int = Field(foreign_key="user.id", index=True)
    template_id: int = Field(foreign_key="template.id")
    status: str = Field(default="draft", index=True, max_length=24)   # draft|queued|running|paused|stopped|done
    run_no: int = 0
    vars_json: str = _text("{}")                             # scan-specific inputs: {context, creds, custom:[{key,value}]}
    authorized_ack_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=now)
    last_run_at: Optional[datetime] = None                    # when the current/last run started
    finished_at: Optional[datetime] = None                    # when the last run completed (for duration)


class ScanShare(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    perm: str = Field(default="read", max_length=16)


class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    value: str = Field(max_length=1024)


class Job(SQLModel, table=True):
    # composite index for the fair-claim + per-scan status counts (hot path at hundreds of thousands of jobs)
    __table_args__ = (Index("ix_job_scan_status_created", "scan_id", "status", "created_at"),)
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    target_id: int = Field(foreign_key="target.id")
    template_id: int = Field(foreign_key="template.id")
    run_no: int = 0
    # the local model this job REQUIRES (an ai_agent template on an ollama profile); empty = any agent can run
    # it. An agent only claims a job whose needs_model it has installed - so a model it can't run is never taken.
    needs_model: str = Field(default="", max_length=120)
    dedup_key: str = Field(index=True, unique=True, max_length=128)
    # opaque per-job run token: integer PKs get reused after a scan is deleted (SQLite reuses rowids), so a
    # stale agent finishing a deleted job could post its result to a REUSED id now owned by a new scan. The
    # agent echoes this token; result/event posts whose token doesn't match the current job are rejected.
    token: str = Field(default="", max_length=32)
    status: str = Field(default="pending", index=True, max_length=24)  # pending|claimed|running|done|failed|cancelled
    runner_id: Optional[int] = Field(default=None, foreign_key="runner.id")
    attempts: int = 0
    argv_json: str = _text("[]")                             # the exact boxcutter command run for this target
    output: str = _text("")                                 # raw engine stdout (report) for the debug view
    claimed_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(default_factory=now)


class Finding(SQLModel, table=True):
    # (scan_id, fingerprint) speeds the per-result diff upsert; (scan_id, severity) speeds the sorted findings list
    __table_args__ = (Index("ix_finding_scan_fp", "scan_id", "fingerprint"),
                      Index("ix_finding_scan_sev", "scan_id", "severity"))
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    target: str = Field(default="", max_length=1024)
    fingerprint: str = Field(index=True, max_length=128)
    template_kind: str = Field(default="", max_length=32)
    severity: str = Field(default="info", max_length=24)
    title: str = Field(default="", max_length=400)
    url: str = Field(default="", max_length=2048)
    cls: str = Field(default="", max_length=120)
    evidence: str = _text("")
    reproduce: str = _text("")
    state: str = Field(default="new", max_length=24)          # new | open | resolved  (auto, from the diff)
    first_seen: datetime = Field(default_factory=now)
    last_seen: datetime = Field(default_factory=now)
    raw_json: str = _text("{}")


class ScanItem(SQLModel, table=True):
    """A non-finding result: a URL, host, endpoint or plain string a workflow/tool emits instead of an issue
    (a crawl, a path-bust, an enum). Kept out of Finding so the findings table stays a list of ISSUES, while
    this data is still listable and downloadable one-per-line instead of being dropped on the floor."""
    __table_args__ = (Index("ix_scanitem_scan_fp", "scan_id", "fingerprint"),)
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    target: str = Field(default="", max_length=1024)
    template_kind: str = Field(default="", max_length=32)
    fingerprint: str = Field(default="", max_length=128)      # of the normalized value; dedupes across reruns
    value: str = Field(default="", max_length=2048)           # the URL / host / item itself
    label: str = Field(default="", max_length=400)            # the engine's title for it, when it had one
    cls: str = Field(default="", max_length=120)
    run_no: int = 0
    first_seen: datetime = Field(default_factory=now)
    last_seen: datetime = Field(default_factory=now)


class JobEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: int = Field(foreign_key="job.id", index=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    seq: int = 0
    phase: str = Field(default="", max_length=64)
    agent: str = Field(default="", max_length=64)
    line: str = _text("")
    reasoning: Optional[str] = Field(default=None, sa_column=Column(Text))
    at: datetime = Field(default_factory=now, index=True)     # indexed for age-based log retention pruning


class Runner(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(default="", max_length=150)
    host: str = Field(default="", max_length=255)
    internal: bool = False                                    # the all-in-one server's built-in agent: a permanent
    #                                                           singleton — concurrency-adjustable but NOT removable
    ip: str = Field(default="", max_length=64)                # the agent host's IP, reported at enroll/heartbeat
    version: str = Field(default="", max_length=40)            # the agent (supervisor) version
    engine_version: str = Field(default="", max_length=64)    # the boxcutter engine the agent actually runs
    status: str = Field(default="idle", max_length=24)        # idle | busy | disconnected (from last_heartbeat)
    slots: int = 1                                            # concurrency the agent currently reports
    desired_slots: Optional[int] = None                       # concurrency the server is asking the agent to adopt
    busy_slots: int = 0
    current_jobs_json: str = _text("[]")
    metrics_json: str = _text("{}")                          # {"cpu": pct, "mem": pct} from the runner heartbeat
    token_hash: str = Field(default="", max_length=128)
    last_heartbeat: Optional[datetime] = None
    enrolled_at: datetime = Field(default_factory=now)


class Activity(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    at: datetime = Field(default_factory=now, index=True)
    kind: str = Field(default="", max_length=40)              # scan_created | job_claimed | scan_done | ...
    message: str = Field(default="", max_length=500)
    scan_id: Optional[int] = Field(default=None, foreign_key="scan.id", index=True)
    runner_id: Optional[int] = Field(default=None, foreign_key="runner.id")
    severity: str = Field(default="info", max_length=16)      # info | warn | critical


class NotifySettings(SQLModel, table=True):
    """Singleton (id=1) — Telegram notification config. The bot token is a server-only secret (never serialized
    to the browser), like LLM api keys."""
    id: Optional[int] = Field(default=1, primary_key=True)
    telegram_enabled: bool = False
    telegram_token: str = _text("")                          # secret, server-only
    telegram_chat_id: str = Field(default="", max_length=64)
    severities_json: str = _text('["Critical", "High"]')     # which finding severities to send


class EnrollToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token_hash: str = Field(index=True, max_length=128)
    label: str = Field(default="", max_length=150)
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")
    created_at: datetime = Field(default_factory=now)
    revoked: bool = False

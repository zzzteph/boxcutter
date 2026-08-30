"""The DB-backed job queue: enqueue, the fair round-robin claim, the stale-job sweeper, and scan completion.

This is the whole broker. No Redis. The claim spreads work across running scans (fair sharing) and uses a
compare-and-swap UPDATE so two agents never grab the same job (works on both SQLite and Postgres)."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select
from sqlalchemy import func, or_, update

from .activity import log_activity
from .config import settings
from .models import Job, LLMProfile, Runner, Scan, Target, Template

_INFLIGHT = ("claimed", "running")


def _needs_model(session: Session, template_id: int) -> str:
    """The local model a template's jobs require: set only for an ai_agent template on an ollama LLM profile.
    Everything else returns "" (any agent can run it)."""
    t = session.get(Template, template_id)
    if not t or t.kind != "ai_agent" or not t.llm_profile_id:
        return ""
    p = session.get(LLMProfile, t.llm_profile_id)
    if p and (p.provider or "").lower() == "ollama" and p.model:
        return p.model
    return ""


def _cap_filter(models):
    """A job is claimable by a runner if it needs no specific model, or the runner has that model installed."""
    have = [m for m in (models or []) if m]
    cond = or_(Job.needs_model == None, Job.needs_model == "")     # noqa: E711
    return or_(cond, Job.needs_model.in_(have)) if have else cond


def dedup_key(scan_id: int, target_id: int, template_id: int, run_no: int) -> str:
    return hashlib.sha256(f"{scan_id}|{target_id}|{template_id}|{run_no}".encode()).hexdigest()


_ENQUEUE_CHUNK = 1000        # job rows flushed per bulk-insert
_TARGET_WINDOW = 5000        # target ids fetched per keyset window


def _iter_target_ids(session: Session, scan_id: int):
    """Yield a scan's target ids in ascending id windows (keyset pagination), so we never materialize the whole
    id list. Each window is a bounded query that completes before we yield, so committing between windows (as
    enqueue_scan does) is safe on both SQLite and Postgres."""
    last = 0
    while True:
        ids = list(session.exec(
            select(Target.id).where(Target.scan_id == scan_id, Target.id > last)
            .order_by(Target.id).limit(_TARGET_WINDOW)).all())
        if not ids:
            return
        yield from ids
        last = ids[-1]


def enqueue_scan(session: Session, scan: Scan) -> int:
    """One pending job per target for the scan's current run_no (unique by scan|target|template|run). Streams
    targets in id windows and bulk-inserts jobs in chunks, holding neither the full target-id list nor the full
    job-row list in memory — so enqueuing millions of targets stays in bounded memory and never wedges the
    request (no per-target SELECT, no ORM-object churn). Flushing per chunk frees the write lock repeatedly
    (matters on SQLite) and lets agents start on the first batches while the rest still enqueue."""
    # Idempotency guard: skip targets already enqueued for THIS run (empty on a fresh run/rerun, which bumps
    # run_no). Bounded by jobs already created for this exact run, so it does not grow with a fresh import.
    existing = set(session.exec(select(Job.dedup_key).where(
        Job.scan_id == scan.id, Job.run_no == scan.run_no)).all())
    created = datetime.now(timezone.utc)
    needs_model = _needs_model(session, scan.template_id)   # gates which agents may claim these jobs
    batch: list[dict] = []
    n = 0
    for tid in _iter_target_ids(session, scan.id):
        key = dedup_key(scan.id, tid, scan.template_id, scan.run_no)
        if key in existing:
            continue
        batch.append({"scan_id": scan.id, "target_id": tid, "template_id": scan.template_id,
                      "run_no": scan.run_no, "dedup_key": key, "token": uuid.uuid4().hex,
                      "status": "pending", "attempts": 0, "needs_model": needs_model,
                      "argv_json": "[]", "output": "", "created_at": created})
        if len(batch) >= _ENQUEUE_CHUNK:
            session.bulk_insert_mappings(Job, batch)
            session.commit()
            n += len(batch)
            batch = []
    if batch:
        session.bulk_insert_mappings(Job, batch)
        session.commit()
        n += len(batch)
    return n


def _next_pending_job_id(session: Session, cap):
    """Fair round-robin: among running scans that still have pending jobs THIS runner can run (cap filter),
    pick the one with the fewest jobs in flight (claimed/running), tie-broken by scan id; then its oldest
    pending job. So with N agents the work spreads one-asset-per-scan before doubling up on any scan, and a
    job whose model the runner lacks is simply never selected for it."""
    running_ids = list(session.exec(select(Scan.id).where(Scan.status == "running")).all())
    if not running_ids:
        return None
    pending = dict(session.exec(select(Job.scan_id, func.count()).where(
        Job.status == "pending", Job.scan_id.in_(running_ids), cap).group_by(Job.scan_id)).all())
    if not pending:
        return None
    inflight = dict(session.exec(select(Job.scan_id, func.count()).where(
        Job.status.in_(_INFLIGHT), Job.scan_id.in_(list(pending))).group_by(Job.scan_id)).all())
    target_scan = min(pending, key=lambda sid: (inflight.get(sid, 0), sid))
    row = session.exec(select(Job.id).where(
        Job.status == "pending", Job.scan_id == target_scan, cap).order_by(Job.created_at).limit(1)).first()
    return row


def claim_job(session: Session, runner: Runner, models=None):
    """Claim one pending job for `runner`, spreading work fairly across running scans and NEVER handing it a job
    whose required local model it does not have installed (`models`). Uses a compare-and-swap UPDATE (WHERE
    status='pending') so concurrent agents never double-claim; retries on contention."""
    cap = _cap_filter(models)
    for _ in range(6):
        job_id = _next_pending_job_id(session, cap)
        if job_id is None:
            return None
        now = datetime.now(timezone.utc)
        res = session.execute(
            update(Job).where(Job.id == job_id, Job.status == "pending")
            .values(status="claimed", runner_id=runner.id, claimed_at=now, attempts=Job.attempts + 1))
        session.commit()
        if res.rowcount == 1:                 # we won the race for this job
            return session.get(Job, job_id)
        # someone else claimed it first; pick another
    return None


def requeue_stale(session: Session) -> int:
    """Return jobs whose runner went silent past the visibility timeout back to the queue (or fail after 3)."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.job_visibility_timeout)
    n = 0
    for job in session.exec(select(Job).where(Job.status.in_(["claimed", "running"]))).all():
        runner = session.get(Runner, job.runner_id) if job.runner_id else None
        hb = runner.last_heartbeat if runner else None
        if hb is not None and hb.tzinfo is None:
            hb = hb.replace(tzinfo=timezone.utc)
        if not runner or hb is None or hb < cutoff:
            # agent went silent -> presume dead; requeue the job (or fail it after the retry cap)
            job.status = "failed" if job.attempts >= settings.job_max_attempts else "pending"
            job.runner_id = None
            job.error = "agent lost (no heartbeat)"
            session.add(job)
            n += 1
    if n:
        session.commit()
        log_activity(session, "agent_lost", f"Requeued {n} job(s) from a lost scanner (no heartbeat)",
                     severity="warn")
    return n


def maybe_finish_scan(session: Session, scan_id: int) -> bool:
    """If a running scan has no unfinished jobs left, mark it done. Returns True when it transitions."""
    left = session.exec(select(Job).where(
        Job.scan_id == scan_id, Job.status.in_(["pending", "claimed", "running"]))).first()
    if left:
        return False
    scan = session.get(Scan, scan_id)
    if scan and scan.status == "running":
        scan.status = "done"
        scan.finished_at = datetime.now(timezone.utc)
        session.add(scan)
        session.commit()
        return True
    return False

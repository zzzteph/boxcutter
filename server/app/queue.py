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
from .models import Job, LLMProfile, Runner, Scan, ScanItem, Stage, Target, Template

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


def dedup_key(scan_id: int, target_id: int, template_id: int, run_no: int, stage_no: int = 0) -> str:
    return hashlib.sha256(f"{scan_id}|{target_id}|{template_id}|{run_no}|{stage_no}".encode()).hexdigest()


_ENQUEUE_CHUNK = 1000        # job rows flushed per bulk-insert
_TARGET_WINDOW = 5000        # target ids fetched per keyset window


def _iter_target_ids(session: Session, scan_id: int, stage_no: int = 0):
    """Yield a scan's target ids FOR ONE STAGE in ascending id windows (keyset pagination), so we never
    materialize the whole id list. Each window is a bounded query that completes before we yield, so committing
    between windows (as enqueue_scan does) is safe on both SQLite and Postgres."""
    last = 0
    while True:
        ids = list(session.exec(
            select(Target.id).where(Target.scan_id == scan_id, Target.stage_no == stage_no, Target.id > last)
            .order_by(Target.id).limit(_TARGET_WINDOW)).all())
        if not ids:
            return
        yield from ids
        last = ids[-1]


def enqueue_scan(session: Session, scan: Scan, stage_no: int = 0, template_id: int | None = None) -> int:
    """One pending job per target of ONE stage for the scan's current run_no (unique by
    scan|target|template|run|stage). Stage 0 (default) is the scan's own template on the uploaded targets;
    later stages are enqueued by ``promote_stage`` on the targets promoted from the previous stage's items.
    Streams targets in id windows and bulk-inserts jobs in chunks, holding neither the full target-id list nor
    the full job-row list in memory — so enqueuing millions of targets stays in bounded memory and never wedges
    the request. Flushing per chunk frees the write lock repeatedly (matters on SQLite) and lets agents start on
    the first batches while the rest still enqueue."""
    template_id = template_id or scan.template_id
    # Idempotency guard: skip targets already enqueued for THIS run+stage (empty on a fresh run/rerun, which
    # bumps run_no). Bounded by jobs already created for this exact run, so it does not grow with a fresh import.
    existing = set(session.exec(select(Job.dedup_key).where(
        Job.scan_id == scan.id, Job.run_no == scan.run_no)).all())
    created = datetime.now(timezone.utc)
    needs_model = _needs_model(session, template_id)        # gates which agents may claim these jobs
    batch: list[dict] = []
    n = 0
    for tid in _iter_target_ids(session, scan.id, stage_no):
        key = dedup_key(scan.id, tid, template_id, scan.run_no, stage_no)
        if key in existing:
            continue
        batch.append({"scan_id": scan.id, "target_id": tid, "template_id": template_id,
                      "run_no": scan.run_no, "stage_no": stage_no, "dedup_key": key, "token": uuid.uuid4().hex,
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


_STAGE_TARGET_CHUNK = 1000        # promoted target rows flushed per bulk-insert


def _filter_items(values: list[str], item_filter: str) -> list[str]:
    """Select which of the previous stage's item values become the next stage's targets. ``all`` keeps every
    value (recon hosts, crawl URLs, ...); ``urls`` keeps only http(s) values (e.g. a crawl feeding a URL-only
    consumer). Unknown filters fall back to ``all``."""
    if item_filter == "urls":
        return [v for v in values if v.startswith(("http://", "https://"))]
    return values


def _ingest_stage_targets(session: Session, scan_id: int, stage_no: int, values) -> int:
    """Insert the promoted values as Target rows for ``stage_no``, de-duped against the targets that stage
    already has (so a rerun's re-promotion doesn't create duplicate targets). Bulk-inserted in chunks. Returns
    the number of NEW target rows created."""
    existing = {v for v in session.exec(select(Target.value).where(
        Target.scan_id == scan_id, Target.stage_no == stage_no)).all()}
    batch: list[dict] = []
    n = 0
    for raw in values:
        v = (raw or "").strip()[:1024]
        if not v or v in existing:
            continue
        existing.add(v)
        batch.append({"scan_id": scan_id, "value": v, "stage_no": stage_no})
        if len(batch) >= _STAGE_TARGET_CHUNK:
            session.bulk_insert_mappings(Target, batch)
            session.commit()
            n += len(batch)
            batch = []
    if batch:
        session.bulk_insert_mappings(Target, batch)
        session.commit()
        n += len(batch)
    return n


def promote_stage(session: Session, scan: Scan, from_stage: int, stage: Stage) -> int:
    """Feed the items the just-finished ``from_stage`` produced THIS run into ``stage``: filter them, materialize
    them as ``stage``'s targets, and enqueue a job per target (fanning out across the fleet). Returns the number
    of jobs enqueued (0 if the previous stage produced nothing to chain — a findings-only stage, or a producer
    that found nothing)."""
    values = [v for v in session.exec(select(ScanItem.value).where(
        ScanItem.scan_id == scan.id, ScanItem.stage_no == from_stage,
        ScanItem.run_no == scan.run_no)).all() if v]
    values = _filter_items(values, stage.item_filter)
    if not values:
        return 0
    _ingest_stage_targets(session, scan.id, stage.stage_no, values)
    return enqueue_scan(session, scan, stage_no=stage.stage_no, template_id=stage.template_id)


def _advance_or_finish(session: Session, scan: Scan) -> bool:
    """Called once a running scan has no unfinished jobs: the current stage LEVEL (frontier) has fully drained.
    Promote to the next declared level that actually has input, or — if none does — mark the scan done. Returns
    True only when the scan is now DONE (so the caller runs the end-of-scan reconcile/notify exactly once).

    A level can hold several stages (a BRANCH: e.g. web-full AND wayback-scan both consuming recon's hosts). The
    whole level is promoted together, and the scan advances if ANY branch in it got work — so a branch is never
    dropped just because a sibling branch happened to be promoted first."""
    frontier = session.exec(select(func.max(Job.stage_no)).where(
        Job.scan_id == scan.id, Job.run_no == scan.run_no)).one() or 0
    later = session.exec(select(Stage).where(
        Stage.scan_id == scan.id, Stage.stage_no > frontier).order_by(Stage.stage_no)).all()
    # Walk the declared levels in order; promote every stage at a level, then advance if the level produced any
    # work. Skip an empty level (e.g. chaining off a findings-only stage) and fall through, so the pipeline never
    # stalls on an empty hand-off.
    for level in sorted({s.stage_no for s in later}):
        promoted = sum(promote_stage(session, scan, from_stage=level - 1, stage=s)
                       for s in later if s.stage_no == level)
        if promoted > 0:
            log_activity(session, "stage_advanced", f"Scan '{scan.name}' → stage {level}", scan_id=scan.id)
            return False                        # advanced; the scan keeps running
    scan.status = "done"
    scan.finished_at = datetime.now(timezone.utc)
    session.add(scan)
    session.commit()
    return True


def maybe_finish_scan(session: Session, scan_id: int) -> bool:
    """If a running scan has no unfinished jobs, EITHER advance it to its next pipeline stage OR mark it done.
    Returns True only when the scan actually finished (all stages drained) — a stage advance returns False, so
    the end-of-scan reconcile/notify fires once, at true completion."""
    left = session.exec(select(Job).where(
        Job.scan_id == scan_id, Job.status.in_(["pending", "claimed", "running"]))).first()
    if left:
        return False
    scan = session.get(Scan, scan_id)
    if scan and scan.status == "running":
        return _advance_or_finish(session, scan)
    return False

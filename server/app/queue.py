"""The DB-backed job queue: enqueue, the fair round-robin claim, the stale-job sweeper, and scan completion.

This is the whole broker. No Redis. The claim spreads work across running scans (fair sharing) and uses a
compare-and-swap UPDATE so two agents never grab the same job (works on both SQLite and Postgres)."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlmodel import Session, select
from sqlalchemy import func, update

from .activity import log_activity
from .config import settings
from .models import Job, Runner, Scan, ScanItem, Schedule, Stage, Target, Template

_INFLIGHT = ("claimed", "running")


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
    batch: list[dict] = []
    n = 0
    for tid in _iter_target_ids(session, scan.id, stage_no):
        key = dedup_key(scan.id, tid, template_id, scan.run_no, stage_no)
        if key in existing:
            continue
        batch.append({"scan_id": scan.id, "target_id": tid, "template_id": template_id,
                      "run_no": scan.run_no, "stage_no": stage_no, "dedup_key": key, "token": uuid.uuid4().hex,
                      "status": "pending", "attempts": 0,
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


def _next_pending_job_id(session: Session):
    """Fair round-robin: among running scans that still have pending jobs, pick the one with the fewest jobs in
    flight (claimed/running), tie-broken by scan id; then its oldest pending job. So with N agents the work
    spreads one-asset-per-scan before doubling up on any scan."""
    running_ids = list(session.exec(select(Scan.id).where(Scan.status == "running")).all())
    if not running_ids:
        return None
    pending = dict(session.exec(select(Job.scan_id, func.count()).where(
        Job.status == "pending", Job.scan_id.in_(running_ids)).group_by(Job.scan_id)).all())
    if not pending:
        return None
    inflight = dict(session.exec(select(Job.scan_id, func.count()).where(
        Job.status.in_(_INFLIGHT), Job.scan_id.in_(list(pending))).group_by(Job.scan_id)).all())
    target_scan = min(pending, key=lambda sid: (inflight.get(sid, 0), sid))
    row = session.exec(select(Job.id).where(
        Job.status == "pending", Job.scan_id == target_scan).order_by(Job.created_at).limit(1)).first()
    return row


def claim_job(session: Session, runner: Runner):
    """Claim one pending job for `runner`, spreading work fairly across running scans. Uses a compare-and-swap
    UPDATE (WHERE status='pending') so concurrent agents never double-claim; retries on contention."""
    for _ in range(6):
        job_id = _next_pending_job_id(session)
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


def rerun_scan(session: Session, scan: Scan) -> int:
    """Re-run a whole scan from stage 0 - the user-less core of the router's /rerun, for the scheduler. Bumps
    run_no (so findings diff against the prior run), clears finished_at, re-enqueues the seed stage."""
    scan.run_no += 1
    scan.last_run_at = datetime.now(timezone.utc)
    scan.finished_at = None
    scan.status = "running"
    session.add(scan)
    session.commit()
    jobs = enqueue_scan(session, scan)
    if jobs == 0:                                            # nothing to do -> resolve straight to done
        maybe_finish_scan(session, scan.id)
    return jobs


def run_due_schedules(session: Session) -> int:
    """Fire every enabled schedule whose next_run_at is due and whose scan isn't already running - the recurring
    perimeter monitor. Called each sweeper cycle. Never raises out (a bad schedule must not kill the sweeper)."""
    now = datetime.now(timezone.utc)
    fired = 0
    due = session.exec(select(Schedule).where(
        Schedule.enabled == True, Schedule.next_run_at <= now)).all()  # noqa: E712
    for sch in due:
        scan = session.get(Scan, sch.scan_id)
        if not scan:                                         # the scan was deleted -> drop the orphan schedule
            session.delete(sch)
            continue
        if scan.status in ("queued", "running", "paused"):
            # DON'T PILE UP. The previous run isn't finished (still running), or the user paused it. Skip this
            # tick and re-check soon (<=5 min) instead of burning the whole interval, so the moment it reaches
            # 'done' the next due check fires it. A run that can't finish (no scanners online, a hung job) just
            # keeps deferring - it never stacks a second copy - and shows as 'running' on the Monitoring page;
            # requeue_stale recovers jobs from lost agents so a run normally self-heals to 'done'.
            sch.next_run_at = now + timedelta(seconds=min(sch.interval_seconds, 300))
            session.add(sch)
            continue
        try:
            jobs = rerun_scan(session, scan)
        except Exception:  # noqa: BLE001 - one bad scan never stops the others / the sweeper
            sch.next_run_at = now + timedelta(seconds=sch.interval_seconds)
            session.add(sch)
            continue
        sch.last_run_at = now
        sch.next_run_at = now + timedelta(seconds=sch.interval_seconds)
        session.add(sch)
        log_activity(session, "scan_scheduled_run",
                     f"Scheduled run of '{scan.name}' (every {sch.interval_seconds}s, {jobs} assets)",
                     scan_id=scan.id)
        fired += 1
    if due:
        session.commit()
    return fired


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
    """Called once a running scan has no unfinished jobs: everything enqueued so far has drained. Promote every
    declared stage whose SOURCE stage has already run (and so is drained) and that hasn't been enqueued yet, then
    — if nothing new could be promoted — mark the scan done. Returns True only when the scan is now DONE (so the
    caller runs the end-of-scan reconcile/notify exactly once).

    Stages form a TREE: each stage consumes one upstream (``from_stage``; -1 means the default stage_no-1 linear
    hand-off). Several stages can share the SAME from_stage — a fan-out BRANCH that runs them in parallel (recon
    -> nuclei AND recon -> sqlmap). Promoting in waves (only off already-drained sources each call) keeps a
    branch's children from starting before the branch itself has produced anything."""
    # stages that already ran this run (have >=1 job). Stage 0 (the seed template) always counts.
    enqueued = {0} | set(session.exec(select(Job.stage_no).where(
        Job.scan_id == scan.id, Job.run_no == scan.run_no).distinct()).all())
    stages = session.exec(select(Stage).where(Stage.scan_id == scan.id).order_by(Stage.stage_no)).all()
    promoted_any = False
    for st in stages:
        if st.stage_no in enqueued:
            continue
        src = st.from_stage if (st.from_stage is not None and st.from_stage >= 0) else st.stage_no - 1
        if src not in enqueued:                 # its source hasn't run/drained yet — a later wave will reach it
            continue
        if promote_stage(session, scan, from_stage=src, stage=st) > 0:
            promoted_any = True
            log_activity(session, "stage_advanced", f"Scan '{scan.name}' → stage {st.stage_no}", scan_id=scan.id)
    if promoted_any:
        return False                            # advanced; the scan keeps running
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


def reconcile_drained_scans(session: Session) -> int:
    """Sweeper safety net: recover any RUNNING scan whose jobs have all finished but which never advanced to its
    next stage or got marked done — e.g. the final result post raced/crashed, or a restart dropped it. For each
    such scan, run the normal advance-or-finish (promote the next stage, or finish + reconcile findings). Without
    this a pipeline could stall forever between stages with nothing left to re-trigger it."""
    n = 0
    for sid in list(session.exec(select(Scan.id).where(Scan.status == "running")).all()):
        # skip a scan still working, or one too fresh to have any jobs yet (mid-enqueue at creation)
        if not session.exec(select(Job.id).where(Job.scan_id == sid).limit(1)).first():
            continue
        if session.exec(select(Job.id).where(
                Job.scan_id == sid, Job.status.in_(_INFLIGHT + ("pending",))).limit(1)).first():
            continue
        if maybe_finish_scan(session, sid):          # it finished -> reconcile findings states + notify, once
            from .diff import reconcile_run
            from .notify import notify
            scan = session.get(Scan, sid)
            stats = reconcile_run(session, scan.id, scan.run_no, scan.last_run_at)
            log_activity(session, "scan_done", f"Scan '{scan.name}' done — "
                         f"{stats['new']} new, {stats['open']} open, {stats['resolved']} resolved", scan_id=scan.id)
            try:
                notify("scan_done", {"scan_id": scan.id, "scan": scan.name, "run_no": scan.run_no, **stats},
                       f"[boxcutter] scan '{scan.name}' done")
            except Exception:  # noqa: BLE001
                pass
        n += 1
    return n

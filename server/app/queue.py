"""The DB-backed job queue and the pipeline engine.

No broker: the jobs table IS the queue. The claim spreads work across running scans (fair sharing) and uses a
compare-and-swap UPDATE so two agents never grab the same job (works on SQLite, Postgres and MySQL).

Every scan runs a stage plan (see pipeline.py). A run starts by enqueueing the stages that read the scan's own
targets. Then results STREAM: as soon as any job finishes, the items it produced are filtered for each stage
that reads from it, turned into that stage's targets and enqueued - so downstream work starts while upstream
work is still running, and every scanner picks up its share. A run is done when nothing is left unfinished."""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, update
from sqlmodel import Session, select

from .activity import log_activity
from .config import settings
from .models import Job, Runner, Scan, Scheduler, Target, Template
from .pipeline import SEED, PlanError, build_plan, children, select_targets

_INFLIGHT = ("claimed", "running")
_UNFINISHED = ("pending", "claimed", "running")
_CHUNK = 1000
# Promotion reads "which targets does this stage already have" and then inserts the rest. The server runs as
# ONE process, so a lock makes that read-then-insert atomic across concurrent result posts.
_PROMOTE_LOCK = threading.RLock()


def dedup_key(scan_id: int, target_id: int, run_no: int, stage: int) -> str:
    return hashlib.sha256(f"{scan_id}|{target_id}|{run_no}|{stage}".encode()).hexdigest()


def load_plan(scan: Scan) -> list[dict]:
    try:
        plan = json.loads(scan.plan_json or "[]")
        return plan if isinstance(plan, list) else []
    except Exception:  # noqa: BLE001
        return []


# ---- enqueue ------------------------------------------------------------------------------------------------
def _enqueue_ids(session: Session, scan: Scan, stage: int, target_ids: list[int]) -> int:
    """One pending job per target for (this run, this stage); idempotent via the unique dedup key."""
    if not target_ids:
        return 0
    created = datetime.now(timezone.utc)
    n = 0
    for i in range(0, len(target_ids), _CHUNK):
        chunk = target_ids[i:i + _CHUNK]
        keys = {tid: dedup_key(scan.id, tid, scan.run_no, stage) for tid in chunk}
        existing = set(session.exec(select(Job.dedup_key).where(Job.dedup_key.in_(list(keys.values())))).all())
        rows = [{"scan_id": scan.id, "target_id": tid, "run_no": scan.run_no, "stage": stage,
                 "dedup_key": k, "token": uuid.uuid4().hex, "status": "pending", "attempts": 0,
                 "argv_json": "[]", "output": "", "created_at": created}
                for tid, k in keys.items() if k not in existing]
        if rows:
            session.bulk_insert_mappings(Job, rows)
            session.commit()
            n += len(rows)
    return n


def _ensure_targets(session: Session, scan_id: int, stage: int, triples: list) -> list[int]:
    """Make sure each (value, key, args) exists as a Target of `stage`; return their ids (existing + new)."""
    ids: list[int] = []
    for i in range(0, len(triples), _CHUNK):
        chunk = triples[i:i + _CHUNK]
        keys = [k for _, k, _ in chunk]
        have = dict(session.exec(select(Target.key, Target.id).where(
            Target.scan_id == scan_id, Target.stage == stage, Target.key.in_(keys))).all())
        new = [{"scan_id": scan_id, "stage": stage, "value": v, "key": k,
                "args_json": json.dumps(a) if a else ""} for v, k, a in chunk if k not in have]
        if new:
            session.bulk_insert_mappings(Target, new)
            session.commit()
            have = dict(session.exec(select(Target.key, Target.id).where(
                Target.scan_id == scan_id, Target.stage == stage, Target.key.in_(keys))).all())
        ids.extend(have[k] for k in keys if k in have)
    return ids


_SEED_WINDOW = 5000


def _seed_windows(session: Session, scan_id: int, only_ids: list[int] | None = None):
    """Yield the scan's own targets as [(id, value)] windows (keyset pagination: bounded memory for huge lists)."""
    if only_ids is not None:
        for i in range(0, len(only_ids), _SEED_WINDOW):
            rows = list(session.exec(select(Target.id, Target.value).where(
                Target.id.in_(only_ids[i:i + _SEED_WINDOW])).order_by(Target.id)).all())
            if rows:
                yield rows
        return
    last = 0
    while True:
        rows = list(session.exec(select(Target.id, Target.value).where(
            Target.scan_id == scan_id, Target.stage == SEED, Target.id > last)
            .order_by(Target.id).limit(_SEED_WINDOW)).all())
        if not rows:
            return
        yield rows
        last = rows[-1][0]


def enqueue_entry_stages(session: Session, scan: Scan, only_seed_ids: list[int] | None = None) -> int:
    """Enqueue every stage that reads the scan's own targets. A stage whose input is 'all' runs on the seed
    rows directly; any other input filters/reshapes them into that stage's own targets first."""
    plan = load_plan(scan)
    entry = [(i, st) for i, st in enumerate(plan) if SEED in st.get("from", [])]
    n = 0
    with _PROMOTE_LOCK:
        for seeds in _seed_windows(session, scan.id, only_seed_ids):
            for i, st in entry:
                if st.get("input", "all") == "all":
                    n += _enqueue_ids(session, scan, i, [tid for tid, _ in seeds])
                else:
                    triples = select_targets(st["input"], [v for _, v in seeds])
                    n += _enqueue_ids(session, scan, i, _ensure_targets(session, scan.id, i, triples))
    return n


def promote_items(session: Session, scan: Scan, stage: int, items: list) -> int:
    """Feed what one finished job (at `stage`) produced into every stage that reads from it."""
    if not items or scan.status not in ("running", "paused"):
        return 0
    plan = load_plan(scan)
    n = 0
    with _PROMOTE_LOCK:
        for child in children(plan, stage):
            triples = select_targets(plan[child].get("input", "all"), items)
            if triples:
                n += _enqueue_ids(session, scan, child, _ensure_targets(session, scan.id, child, triples))
    return n


# ---- run lifecycle ------------------------------------------------------------------------------------------
def start_run(session: Session, scan: Scan) -> int:
    """Start a (new) run of a scan: snapshot the current plan of its template, bump run_no, cancel anything
    left over from the previous run, and enqueue the entry stages. Returns the jobs enqueued."""
    tmpl = session.get(Template, scan.template_id) if scan.template_id else None
    if tmpl is not None:
        try:
            scan.plan_json = json.dumps(build_plan(session, tmpl))
        except PlanError:
            pass                                 # keep the last good plan if the template is now broken
        scan.template_name = tmpl.title or tmpl.name
    if not load_plan(scan):
        raise PlanError("this scan has nothing to run (its template was deleted)")
    session.execute(update(Job).where(Job.scan_id == scan.id, Job.status.in_(_UNFINISHED))
                    .values(status="cancelled"))
    scan.run_no += 1
    scan.status = "running"
    scan.last_run_at = datetime.now(timezone.utc)
    scan.finished_at = None
    session.add(scan)
    session.commit()
    n = enqueue_entry_stages(session, scan)
    if n == 0:
        maybe_finish_scan(session, scan.id)
    return n


def maybe_finish_scan(session: Session, scan_id: int) -> bool:
    """A running scan with nothing unfinished in its current run is done. Returns True when it just finished."""
    scan = session.get(Scan, scan_id)
    if not scan or scan.status != "running":
        return False
    left = session.exec(select(Job.id).where(Job.scan_id == scan_id, Job.run_no == scan.run_no,
                                             Job.status.in_(_UNFINISHED)).limit(1)).first()
    if left is not None:
        return False
    res = session.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "running")
                          .values(status="done", finished_at=datetime.now(timezone.utc)))
    session.commit()
    return res.rowcount == 1


def on_scan_done(session: Session, scan: Scan) -> None:
    """Reconcile finding states for the finished run, log it and notify (once per run)."""
    from .diff import reconcile_run
    from .notify import notify_scan_done
    stats = reconcile_run(session, scan.id, scan.run_no, scan.last_run_at)
    log_activity(session, "scan_done", f"Scan '{scan.name}' done — "
                 f"{stats['new']} new, {stats['open']} open, {stats['resolved']} resolved", scan_id=scan.id)
    try:
        notify_scan_done(session, scan, stats)
    except Exception:  # noqa: BLE001 - notifications are best-effort
        pass


# ---- claim --------------------------------------------------------------------------------------------------
def _next_pending_job_id(session: Session):
    """Fair round-robin: among running scans that still have pending jobs, pick the one with the fewest jobs in
    flight, tie-broken by scan id; then its oldest pending job."""
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
    return session.exec(select(Job.id).where(
        Job.status == "pending", Job.scan_id == target_scan).order_by(Job.created_at, Job.id).limit(1)).first()


def claim_job(session: Session, runner: Runner):
    """Claim one pending job for `runner` (compare-and-swap; retries on contention)."""
    for _ in range(6):
        job_id = _next_pending_job_id(session)
        if job_id is None:
            return None
        res = session.execute(
            update(Job).where(Job.id == job_id, Job.status == "pending")
            .values(status="claimed", runner_id=runner.id, claimed_at=datetime.now(timezone.utc),
                    attempts=Job.attempts + 1))
        session.commit()
        if res.rowcount == 1:
            return session.get(Job, job_id)
    return None


# ---- sweeper ------------------------------------------------------------------------------------------------
def requeue_stale(session: Session) -> int:
    """Return jobs whose runner went silent past the visibility timeout to the queue (or fail after N tries)."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.job_visibility_timeout)
    n = 0
    for job in session.exec(select(Job).where(Job.status.in_(_INFLIGHT))).all():
        runner = session.get(Runner, job.runner_id) if job.runner_id else None
        hb = runner.last_heartbeat if runner else None
        if hb is not None and hb.tzinfo is None:
            hb = hb.replace(tzinfo=timezone.utc)
        if not runner or hb is None or hb < cutoff:
            job.status = "failed" if job.attempts >= settings.job_max_attempts else "pending"
            job.runner_id = None
            job.error = "scanner lost (no heartbeat)"
            session.add(job)
            n += 1
    if n:
        session.commit()
        log_activity(session, "agent_lost", f"Requeued {n} job(s) from a lost scanner (no heartbeat)",
                     severity="warn")
    return n


def reconcile_drained_scans(session: Session) -> int:
    """Safety net: finish any running scan whose jobs have all finished (e.g. the final result post crashed)."""
    n = 0
    for sid in list(session.exec(select(Scan.id).where(Scan.status == "running")).all()):
        if maybe_finish_scan(session, sid):
            on_scan_done(session, session.get(Scan, sid))
            n += 1
    return n


def fire_scheduler(session: Session, sch: Scheduler, now: datetime | None = None) -> int:
    """Run a scheduler's scan now (creating it on first use). Returns jobs enqueued."""
    from .routers.scans import ingest_targets           # lazy: avoid an import cycle
    now = now or datetime.now(timezone.utc)
    scan = session.get(Scan, sch.scan_id) if sch.scan_id else None
    if scan is None:
        tmpl = session.get(Template, sch.template_id)
        scan = Scan(name=sch.name, template_id=sch.template_id, scheduler_id=sch.id, status="queued",
                    template_name=(tmpl.title or tmpl.name) if tmpl else "", vars_json=sch.vars_json or "{}")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        ingest_targets(session, scan.id, (sch.targets_text or "").splitlines())
        sch.scan_id = scan.id
    jobs = start_run(session, scan)
    sch.last_run_at = now
    sch.next_run_at = now + timedelta(seconds=sch.interval_seconds)
    session.add(sch)
    session.commit()
    log_activity(session, "scheduled_run", f"Scheduler '{sch.name}' started run #{scan.run_no} ({jobs} jobs)",
                 scan_id=scan.id)
    return jobs


def run_due_schedulers(session: Session) -> int:
    """Fire every enabled scheduler that is due. A previous run that is still going is never stacked: the
    scheduler re-checks in a few minutes instead."""
    now = datetime.now(timezone.utc)
    fired = 0
    for sch in session.exec(select(Scheduler).where(Scheduler.enabled == True,  # noqa: E712
                                                    Scheduler.next_run_at <= now)).all():
        scan = session.get(Scan, sch.scan_id) if sch.scan_id else None
        if scan is not None and scan.status in ("running", "paused"):
            sch.next_run_at = now + timedelta(seconds=min(sch.interval_seconds, 300))
            session.add(sch)
            session.commit()
            continue
        try:
            fire_scheduler(session, sch, now)
            fired += 1
        except Exception as e:  # noqa: BLE001 - one bad scheduler never stops the others / the sweeper
            session.rollback()
            sch = session.get(Scheduler, sch.id)
            if sch is not None:
                sch.next_run_at = now + timedelta(seconds=sch.interval_seconds)
                session.add(sch)
                session.commit()
                log_activity(session, "scheduler_failed", f"Scheduler '{sch.name}' could not start: {e}",
                             severity="warn")
    return fired

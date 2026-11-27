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

from sqlalchemy import delete, func, update
from sqlmodel import Session, select

from .activity import log_activity
from .cron import CronError, next_runs
from .config import settings
from .models import Job, Runner, Scan, Scheduler, Target, Template
from .pipeline import SEED, PlanError, build_plan, children, select_targets
from .window import is_open, parse as parse_window

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


def _ensure_targets(session: Session, scan_id: int, stage: int, triples: list,
                    new_keys: set | None = None) -> list[int]:
    """Make sure each (value, key, args, ...) exists as a Target of `stage`; return their ids (existing + new).
    Keys inserted by this call are added to `new_keys` when given."""
    ids: list[int] = []
    for i in range(0, len(triples), _CHUNK):
        chunk = triples[i:i + _CHUNK]
        keys = [t[1] for t in chunk]
        have = dict(session.exec(select(Target.key, Target.id).where(
            Target.scan_id == scan_id, Target.stage == stage, Target.key.in_(keys))).all())
        new = [{"scan_id": scan_id, "stage": stage, "value": t[0], "key": t[1],
                "args_json": json.dumps(t[2]) if t[2] else ""} for t in chunk if t[1] not in have]
        if new:
            session.bulk_insert_mappings(Target, new)
            session.commit()
            if new_keys is not None:
                new_keys.update(r["key"] for r in new)
            have = dict(session.exec(select(Target.key, Target.id).where(
                Target.scan_id == scan_id, Target.stage == stage, Target.key.in_(keys))).all())
        ids.extend(have[k] for k in keys if k in have)
    return ids


def _feed(session: Session, scan: Scan, plan: list[dict], stage: int, items: list) -> int:
    """Hand `items` to one stage. A normal stage gets one pending job per new target; a MERGE stage runs no
    job - every item it has not seen yet this run is passed straight on to the stages after it."""
    st = plan[stage]
    if st.get("kind") == "merge":
        quads = select_targets(st.get("input", "all"), items, with_items=True)
        if not quads:
            return 0
        fresh: set = set()
        _ensure_targets(session, scan.id, stage, quads, fresh)
        out = [q[3] for q in quads if q[1] in fresh]
        n = 0
        if out:
            for child in children(plan, stage):
                n += _feed(session, scan, plan, child, out)
        return n
    triples = select_targets(st.get("input", "all"), items)
    if not triples:
        return 0
    return _enqueue_ids(session, scan, stage, _ensure_targets(session, scan.id, stage, triples))


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
                if st.get("input", "all") == "all" and st.get("kind") != "merge":
                    n += _enqueue_ids(session, scan, i, [tid for tid, _ in seeds])
                else:
                    n += _feed(session, scan, plan, i, [v for _, v in seeds])
    return n


def promote_items(session: Session, scan: Scan, stage: int, items: list) -> int:
    """Feed what one finished job (at `stage`) produced into every stage that reads from it."""
    if not items or scan.status not in ("running", "paused"):
        return 0
    plan = load_plan(scan)
    n = 0
    with _PROMOTE_LOCK:
        for child in children(plan, stage):
            n += _feed(session, scan, plan, child, items)
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
    # a merge de-duplicates per run: forget what it passed on last time
    merges = [i for i, st in enumerate(load_plan(scan)) if st.get("kind") == "merge"]
    if merges:
        session.execute(delete(Target).where(Target.scan_id == scan.id, Target.stage.in_(merges)))
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
    scan.removed_last_run = stats["removed"]
    session.add(scan)
    session.commit()
    msg = f"Scan '{scan.name}' run #{scan.run_no} done — {stats['new']} new, {stats['open']} still open"
    if stats["removed"]:
        msg += f", {stats['removed']} no longer found (removed)"
    if stats["unconfirmed"]:
        msg += f", {stats['unconfirmed']} could not be re-checked"
    log_activity(session, "scan_done", msg, scan_id=scan.id)
    for f in stats["removed_list"][:20]:                 # what got fixed, one line each
        log_activity(session, "finding_removed", f"No longer found: [{f['severity']}] {f['title']} on {f['target']}",
                     scan_id=scan.id)
    if len(stats["removed_list"]) > 20:
        log_activity(session, "finding_removed", f"…and {len(stats['removed_list']) - 20} more no longer found",
                     scan_id=scan.id)
    try:
        notify_scan_done(session, scan, stats)
    except Exception:  # noqa: BLE001 - notifications are best-effort
        pass


# ---- claim --------------------------------------------------------------------------------------------------
def _next_pending_job_id(session: Session):
    """Fair round-robin: among running scans that still have pending jobs, pick the one with the fewest jobs in
    flight, tie-broken by scan id; then its oldest pending job."""
    now = datetime.now(timezone.utc)
    running_ids = [sid for sid, w in session.exec(select(Scan.id, Scan.window_json).where(
        Scan.status == "running")).all() if is_open(parse_window(w), now)]      # outside its window: wait
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
    scan.window_json = sch.window_json or ""
    jobs = start_run(session, scan)
    sch.last_run_at = now
    sch.next_run_at = next_run(sch, now)
    session.add(sch)
    session.commit()
    log_activity(session, "scheduled_run", f"Scheduler '{sch.name}' started run #{scan.run_no} ({jobs} jobs)",
                 scan_id=scan.id)
    return jobs


def next_run(sch: Scheduler, after: datetime | None = None) -> datetime | None:
    """The scheduler's next cron tick after `after` (default now), or None if the expression is unusable."""
    try:
        return next_runs(sch.cron, sch.timezone, 1, after)[0]
    except CronError:
        return None


def run_due_schedulers(session: Session) -> int:
    """Fire every enabled scheduler that is due. Runs never stack: if the previous run is still going when the
    next tick comes, that tick is skipped (and logged) and the scheduler waits for the one after."""
    now = datetime.now(timezone.utc)
    fired = 0
    for sch in session.exec(select(Scheduler).where(Scheduler.enabled == True,  # noqa: E712
                                                    Scheduler.next_run_at <= now)).all():
        scan = session.get(Scan, sch.scan_id) if sch.scan_id else None
        if scan is not None and scan.status in ("running", "paused"):
            sch.next_run_at = next_run(sch, now)
            session.add(sch)
            session.commit()
            log_activity(session, "scheduled_run_skipped",
                         f"Scheduler '{sch.name}': skipped a run — the previous one is still {scan.status}",
                         scan_id=scan.id, severity="warn")
            continue
        try:
            fire_scheduler(session, sch, now)
            fired += 1
        except Exception as e:  # noqa: BLE001 - one bad scheduler never stops the others / the sweeper
            session.rollback()
            sch = session.get(Scheduler, sch.id)
            if sch is not None:
                sch.next_run_at = next_run(sch, now)
                session.add(sch)
                session.commit()
                log_activity(session, "scheduler_failed", f"Scheduler '{sch.name}' could not start: {e}",
                             severity="warn")
    return fired

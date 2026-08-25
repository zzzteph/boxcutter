"""Activity feed: a clickable log of everything that happens (scan lifecycle, scanner claims, failures, …).
Best-effort — recording activity must never break the action that triggered it."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func
from sqlmodel import Session, select

from .models import Activity, JobEvent


def log_activity(session: Session, kind: str, message: str, scan_id: int | None = None,
                 runner_id: int | None = None, severity: str = "info") -> None:
    try:
        session.add(Activity(kind=kind, message=message[:400], scan_id=scan_id,
                             runner_id=runner_id, severity=severity))
        session.commit()
    except Exception:  # noqa: BLE001 - never let logging break the caller
        session.rollback()


def prune_logs(session: Session, days: int) -> int:
    """Delete Activity + JobEvent rows older than `days` (both `at` columns are indexed), so these append-only
    log tables can't grow without bound. Set-based DELETE; a no-op when days <= 0. Returns rows removed."""
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    try:
        r1 = session.execute(delete(Activity).where(Activity.at < cutoff))
        r2 = session.execute(delete(JobEvent).where(JobEvent.at < cutoff))
        session.commit()
        return (r1.rowcount or 0) + (r2.rowcount or 0)
    except Exception:  # noqa: BLE001 - pruning must never break the sweeper
        session.rollback()
        return 0


def cap_job_events(session: Session, max_per_job: int, max_jobs: int = 300) -> int:
    """Bound the live log by SIZE (not just age): keep only the newest `max_per_job` JobEvents per job — a ring
    buffer — so a chatty --debug/--steps run (or a huge multi-target scan) can't balloon the table between the
    age-based prunes. Trims the most-bloated jobs first, a bounded batch per call, so one pass is cheap and it
    catches up over cycles. The full engine output still lives in Job.output (Raw output). No-op when
    max_per_job <= 0. Returns rows removed."""
    if max_per_job <= 0:
        return 0
    removed = 0
    try:
        over = session.execute(                       # jobs whose live log exceeds the cap, worst offenders first
            select(JobEvent.job_id).group_by(JobEvent.job_id)
            .having(func.count() > max_per_job).order_by(func.count().desc()).limit(max_jobs)).all()
        for (job_id,) in over:
            # the oldest event we KEEP = the max_per_job-th newest for this job; delete everything older than it
            cutoff = session.execute(
                select(JobEvent.id).where(JobEvent.job_id == job_id)
                .order_by(JobEvent.id.desc()).offset(max_per_job - 1).limit(1)).scalar()
            if cutoff is None:
                continue
            r = session.execute(delete(JobEvent).where(JobEvent.job_id == job_id, JobEvent.id < cutoff))
            removed += r.rowcount or 0
        session.commit()
        return removed
    except Exception:  # noqa: BLE001 - trimming must never break the sweeper
        session.rollback()
        return 0

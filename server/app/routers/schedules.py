"""Scheduled scans - continuous perimeter monitoring. A Schedule re-runs an existing scan every N seconds (the
server's sweeper fires it via queue.run_due_schedules), so the scan's findings diff over time: new issues show
as 'new', fixed ones flip to 'resolved'. One schedule per scan; it re-runs the SAME scan to keep that history.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import Scan, Schedule, User
from ..security import current_user

router = APIRouter(prefix="/schedules", tags=["scans"])

_MIN_INTERVAL = 300             # 5 min floor - the sweeper runs ~every 30s, but don't let a scan hammer itself
_MAX_INTERVAL = 30 * 24 * 3600  # 30 days


def _brief(session: Session, s: Schedule) -> dict:
    scan = session.get(Scan, s.scan_id)
    return {"id": s.id, "scan_id": s.scan_id, "scan_name": scan.name if scan else "(deleted)",
            "scan_status": scan.status if scan else None, "interval_seconds": s.interval_seconds,
            "enabled": s.enabled, "last_run_at": s.last_run_at, "next_run_at": s.next_run_at,
            "created_at": s.created_at}


@router.get("")
def list_schedules(user: User = Depends(current_user), session: Session = Depends(get_session)):
    rows = session.exec(select(Schedule).order_by(Schedule.id.desc())).all()
    return [_brief(session, s) for s in rows]


class ScheduleIn(BaseModel):
    interval_seconds: int = 3600
    enabled: bool = True


@router.put("/{scan_id}")
def upsert_schedule(scan_id: int, body: ScheduleIn, user: User = Depends(current_user),
                    session: Session = Depends(get_session)):
    """Create or update the schedule for a scan. Clamps the interval to a sane floor/ceiling and sets the next
    run one interval out (so enabling doesn't fire an immediate duplicate of a run you just started)."""
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    interval = max(_MIN_INTERVAL, min(int(body.interval_seconds or 3600), _MAX_INTERVAL))
    now = datetime.now(timezone.utc)
    sch = session.exec(select(Schedule).where(Schedule.scan_id == scan_id)).first()
    if not sch:
        sch = Schedule(scan_id=scan_id, created_by=user.id)
    sch.interval_seconds = interval
    sch.enabled = bool(body.enabled)
    sch.next_run_at = now + timedelta(seconds=interval) if sch.enabled else None
    session.add(sch)
    session.commit()
    session.refresh(sch)
    return _brief(session, sch)


@router.get("/{scan_id}")
def get_schedule(scan_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    sch = session.exec(select(Schedule).where(Schedule.scan_id == scan_id)).first()
    return _brief(session, sch) if sch else None


@router.delete("/{scan_id}")
def delete_schedule(scan_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    sch = session.exec(select(Schedule).where(Schedule.scan_id == scan_id)).first()
    if sch:
        session.delete(sch)
        session.commit()
    return {"ok": True}

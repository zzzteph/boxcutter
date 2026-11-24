"""Schedulers: a named, recurring scan - what to run, on what, and a cron schedule. Each one owns a Scan that it
re-runs on every tick, so the findings diff over time (new / open / resolved)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete
from sqlmodel import Session, select

from ..activity import log_activity
from ..cron import CronError, describe, next_runs, validate
from ..db import get_session
from ..models import Scan, Scheduler, Target, Template
from ..pipeline import SEED
from ..queue import fire_scheduler, next_run
from .scans import ingest_targets

router = APIRouter(prefix="/schedulers", tags=["schedulers"])


def _out(session: Session, s: Scheduler) -> dict:
    tmpl = session.get(Template, s.template_id)
    scan = session.get(Scan, s.scan_id) if s.scan_id else None
    targets = [ln for ln in (s.targets_text or "").splitlines() if ln.strip()]
    return {"id": s.id, "name": s.name, "template_id": s.template_id,
            "template": (tmpl.title or tmpl.name) if tmpl else "(deleted)",
            "template_kind": tmpl.kind if tmpl else "", "cron": s.cron, "timezone": s.timezone,
            "schedule": describe(s.cron), "enabled": s.enabled, "targets": targets, "targets_count": len(targets),
            "vars": json.loads(s.vars_json or "{}"), "scan_id": s.scan_id,
            "scan_status": scan.status if scan else None, "run_no": scan.run_no if scan else 0,
            "last_run_at": s.last_run_at, "next_run_at": s.next_run_at, "created_at": s.created_at}


@router.get("")
def list_schedulers(session: Session = Depends(get_session)):
    return [_out(session, s) for s in session.exec(select(Scheduler).order_by(Scheduler.id.desc())).all()]


@router.get("/cron-preview")
def cron_preview(expr: str, tz: str = "UTC"):
    """Live check for the cron field: is it valid, what does it mean, when are the next runs."""
    try:
        e = validate(expr, tz)
        return {"ok": True, "error": "", "cron": e, "description": describe(e),
                "next": [d.isoformat() for d in next_runs(e, tz, 3)]}
    except CronError as err:
        return {"ok": False, "error": str(err), "cron": expr, "description": "", "next": []}


class SchedulerIn(BaseModel):
    name: str | None = None
    template_id: int | None = None
    targets: list[str] | None = None
    cron: str | None = None
    timezone: str | None = None
    enabled: bool | None = None
    vars: dict | None = None
    start_now: bool = False


def _cron(expr: str, tz: str) -> str:
    try:
        return validate(expr, tz)
    except CronError as e:
        raise HTTPException(400, str(e))


@router.post("")
def create_scheduler(body: SchedulerIn, session: Session = Depends(get_session)):
    tmpl = session.get(Template, body.template_id or 0)
    if tmpl is None:
        raise HTTPException(400, "pick what to run")
    targets = [t.strip() for t in (body.targets or []) if t.strip()]
    if not targets:
        raise HTTPException(400, "add at least one target")
    tz = body.timezone or "UTC"
    sch = Scheduler(name=(body.name or tmpl.title or tmpl.name).strip()[:200], template_id=tmpl.id,
                    targets_text="\n".join(targets), cron=_cron(body.cron or "0 3 * * *", tz), timezone=tz,
                    enabled=True if body.enabled is None else body.enabled, vars_json=json.dumps(body.vars or {}))
    sch.next_run_at = next_run(sch) if sch.enabled else None
    session.add(sch)
    session.commit()
    session.refresh(sch)
    log_activity(session, "scheduler_created", f"Scheduler '{sch.name}' created ({describe(sch.cron)})")
    if body.start_now and sch.enabled:
        fire_scheduler(session, sch)
    return _out(session, sch)


@router.get("/{sid}")
def get_scheduler(sid: int, session: Session = Depends(get_session)):
    s = session.get(Scheduler, sid)
    if not s:
        raise HTTPException(404)
    return _out(session, s)


@router.patch("/{sid}")
def update_scheduler(sid: int, body: SchedulerIn, session: Session = Depends(get_session)):
    s = session.get(Scheduler, sid)
    if not s:
        raise HTTPException(404)
    scan = session.get(Scan, s.scan_id) if s.scan_id else None
    if body.name is not None and body.name.strip():
        s.name = body.name.strip()[:200]
        if scan:
            scan.name = s.name
    if body.template_id is not None and body.template_id != s.template_id:
        tmpl = session.get(Template, body.template_id)
        if tmpl is None:
            raise HTTPException(400, "template not found")
        s.template_id = tmpl.id
        if scan:                               # takes effect on the next run
            scan.template_id, scan.template_name = tmpl.id, tmpl.title or tmpl.name
    if body.cron is not None or body.timezone is not None:
        tz = body.timezone or s.timezone
        s.cron, s.timezone = _cron(body.cron or s.cron, tz), tz
    if body.enabled is not None:
        s.enabled = body.enabled
    s.next_run_at = next_run(s) if s.enabled else None
    if body.vars is not None:
        s.vars_json = json.dumps(body.vars)
        if scan:
            scan.vars_json = s.vars_json
    if body.targets is not None:
        targets = [t.strip() for t in body.targets if t.strip()]
        if not targets:
            raise HTTPException(400, "add at least one target")
        s.targets_text = "\n".join(targets)
        if scan and scan.status not in ("running", "paused"):
            session.execute(delete(Target).where(Target.scan_id == scan.id, Target.stage == SEED))
            session.commit()
            ingest_targets(session, scan.id, targets)
    if scan:
        session.add(scan)
    session.add(s)
    session.commit()
    return _out(session, s)


@router.post("/{sid}/run")
def run_now(sid: int, session: Session = Depends(get_session)):
    s = session.get(Scheduler, sid)
    if not s:
        raise HTTPException(404)
    scan = session.get(Scan, s.scan_id) if s.scan_id else None
    if scan is not None and scan.status in ("running", "paused"):
        raise HTTPException(400, "the previous run is still going")
    jobs = fire_scheduler(session, s, datetime.now(timezone.utc))
    return {**_out(session, s), "jobs": jobs}


@router.delete("/{sid}")
def delete_scheduler(sid: int, session: Session = Depends(get_session)):
    """Delete the schedule. Its scan (with all past results) stays and can still be run by hand."""
    s = session.get(Scheduler, sid)
    if s:
        scan = session.get(Scan, s.scan_id) if s.scan_id else None
        if scan:
            scan.scheduler_id = None
            session.add(scan)
        session.delete(s)
        session.commit()
        log_activity(session, "scheduler_deleted", f"Scheduler '{s.name}' deleted")
    return {"ok": True}

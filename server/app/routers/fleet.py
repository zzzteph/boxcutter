"""UI endpoints for the scanner fleet, enroll tokens, the dashboard stats, the activity feed and the global
findings list."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import case, func, or_
from sqlmodel import Session, select

from ..activity import log_activity
from ..db import get_session
from ..models import Activity, EnrollToken, Finding, Job, Runner, Scan, Scheduler, Target
from ..security import hash_token

router = APIRouter(tags=["fleet"])


def _aware(dt):
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _connected(r: Runner) -> bool:
    hb = _aware(r.last_heartbeat)
    return hb is not None and hb > datetime.now(timezone.utc) - timedelta(seconds=45)


def _runner_row(r: Runner) -> dict:
    connected = _connected(r)
    return {"id": r.id, "name": r.name, "host": r.host, "ip": r.ip, "version": r.version,
            "engine_version": r.engine_version, "internal": r.internal,
            "status": r.status if connected else "disconnected", "connected": connected,
            "slots": r.slots, "desired_slots": r.desired_slots, "busy_slots": r.busy_slots,
            "current_jobs": json.loads(r.current_jobs_json or "[]"),
            "metrics": json.loads(r.metrics_json or "{}"),
            "last_heartbeat": r.last_heartbeat, "enrolled_at": r.enrolled_at}


def _job_brief(session: Session, job: Job) -> dict:
    t = session.get(Target, job.target_id)
    scan = session.get(Scan, job.scan_id)
    step = ""
    if scan:
        try:
            plan = json.loads(scan.plan_json or "[]")
            step = plan[job.stage].get("title", "") if 0 <= job.stage < len(plan) else ""
        except Exception:  # noqa: BLE001
            step = ""
    dur = round((job.finished_at - job.claimed_at).total_seconds(), 1) if job.claimed_at and job.finished_at else None
    return {"id": job.id, "scan_id": job.scan_id, "scan": scan.name if scan else "", "target": t.value if t else "",
            "template": step, "status": job.status, "claimed_at": job.claimed_at,
            "finished_at": job.finished_at, "duration_sec": dur}


@router.get("/runners")
def fleet(session: Session = Depends(get_session)):
    rows = []
    for r in session.exec(select(Runner).order_by(Runner.id)).all():
        row = _runner_row(r)
        row["current"] = [_job_brief(session, j) for j in
                          (session.get(Job, jid) for jid in row["current_jobs"][:16]) if j]
        rows.append(row)
    return rows


@router.get("/runners/{runner_id}")
def runner_detail(runner_id: int, session: Session = Depends(get_session)):
    r = session.get(Runner, runner_id)
    if not r:
        raise HTTPException(404)
    row = _runner_row(r)
    row["current"] = [_job_brief(session, j) for j in (session.get(Job, jid) for jid in row["current_jobs"]) if j]
    last = session.exec(select(Job).where(Job.runner_id == runner_id, Job.finished_at != None)  # noqa: E711
                        .order_by(Job.finished_at.desc()).limit(12)).all()
    row["last_jobs"] = [_job_brief(session, j) for j in last]
    return row


class RunnerPatch(BaseModel):
    concurrency: int


@router.patch("/runners/{runner_id}")
def set_runner_concurrency(runner_id: int, body: RunnerPatch, session: Session = Depends(get_session)):
    """Ask an agent to run more/fewer parallel jobs; it adopts the value on its next heartbeat (≤10s)."""
    r = session.get(Runner, runner_id)
    if not r:
        raise HTTPException(404)
    r.desired_slots = max(0, min(int(body.concurrency), 32))
    session.add(r)
    session.commit()
    log_activity(session, "runner_concurrency", f"Asked '{r.name or r.id}' to run {r.desired_slots} job(s)",
                 runner_id=r.id)
    return _runner_row(r)


@router.delete("/runners/{runner_id}")
def delete_runner(runner_id: int, session: Session = Depends(get_session)):
    r = session.get(Runner, runner_id)
    if not r:
        raise HTTPException(404)
    if r.internal:
        raise HTTPException(400, "the built-in scanner can't be removed — set its concurrency to 0 to idle it")
    for job in session.exec(select(Job).where(Job.runner_id == runner_id)).all():
        if job.status in ("claimed", "running"):
            job.status = "pending"
        job.runner_id = None
        session.add(job)
    name = r.name or f"scanner #{r.id}"
    session.delete(r)
    session.commit()
    log_activity(session, "runner_deleted", f"Scanner '{name}' removed", severity="warn")
    return {"ok": True}


# ---- enroll tokens ------------------------------------------------------------------------------------------
class EnrollTokenIn(BaseModel):
    label: str = ""


@router.get("/enroll-tokens")
def list_enroll_tokens(session: Session = Depends(get_session)):
    rows = session.exec(select(EnrollToken).where(EnrollToken.revoked == False)  # noqa: E712
                        .order_by(EnrollToken.id.desc())).all()
    return [{"id": t.id, "label": t.label, "prefix": t.prefix, "created_at": t.created_at} for t in rows]


@router.post("/enroll-tokens")
def create_enroll_token(body: EnrollTokenIn, session: Session = Depends(get_session)):
    token = secrets.token_urlsafe(24)
    session.add(EnrollToken(token_hash=hash_token(token), label=body.label[:150], prefix=token[:6]))
    session.commit()
    return {"token": token}     # shown once; only the hash is stored


@router.delete("/enroll-tokens/{tid}")
def revoke_enroll_token(tid: int, session: Session = Depends(get_session)):
    t = session.get(EnrollToken, tid)
    if t:
        t.revoked = True
        session.add(t)
        session.commit()
    return {"ok": True}


# ---- findings across all scans ------------------------------------------------------------------------------
_SEV_RANK = ["Critical", "High", "Medium", "Low", "Info"]
_SORTS = {"title": Finding.title, "target": Finding.target, "scan": Scan.name, "state": Finding.state,
          "last_seen": Finding.last_seen}


def _order(sort: str, dir: str):
    if sort == "severity":
        col = case(*[(Finding.severity == s, i) for i, s in enumerate(_SEV_RANK)], else_=len(_SEV_RANK))
    else:
        col = _SORTS.get(sort, Finding.last_seen)
    return col.desc() if dir == "desc" else col.asc()


@router.get("/findings")
def global_findings(severity: str | None = None, state: str | None = None, q: str | None = None,
                    scan_id: int | None = None, sort: str = "last_seen", dir: str = "desc",
                    limit: int = 50, offset: int = 0, session: Session = Depends(get_session)):
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    conds = []
    if scan_id is not None:
        conds.append(Finding.scan_id == scan_id)
    if state in ("new", "open", "unconfirmed"):
        conds.append(Finding.state == state)
    if severity:
        conds.append(Finding.severity == severity)
    if q:
        like = f"%{q}%"
        conds.append(or_(Finding.title.ilike(like), Finding.target.ilike(like),
                         Finding.url.ilike(like), Finding.cls.ilike(like)))
    base = select(Finding, Scan.name).join(Scan, Scan.id == Finding.scan_id)
    count_stmt = select(func.count()).select_from(Finding).join(Scan, Scan.id == Finding.scan_id)
    if conds:
        base, count_stmt = base.where(*conds), count_stmt.where(*conds)
    total = session.exec(count_stmt).one()
    rows = session.exec(base.order_by(_order(sort, dir), Finding.id.desc()).offset(offset).limit(limit)).all()
    items = [{"id": f.id, "scan_id": f.scan_id, "scan": name, "severity": f.severity, "title": f.title,
              "target": f.target, "url": f.url, "cls": f.cls, "state": f.state, "last_seen": f.last_seen}
             for f, name in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


# ---- dashboard + activity -----------------------------------------------------------------------------------
@router.get("/stats")
def stats(session: Session = Depends(get_session)):
    now = datetime.now(timezone.utc)
    scans_by_status = dict(session.exec(select(Scan.status, func.count()).group_by(Scan.status)).all())
    by_sev = dict(session.exec(select(Finding.severity, func.count()).group_by(Finding.severity)).all())
    findings_new = session.exec(select(func.count()).select_from(Finding).where(Finding.state == "new")).one()
    removed_last_runs = session.exec(select(func.coalesce(func.sum(Scan.removed_last_run), 0))).one()
    runners = session.exec(select(Runner)).all()
    slots_total = sum(r.slots for r in runners if _connected(r))
    slots_busy = sum(r.busy_slots for r in runners if _connected(r))
    crits = session.exec(select(Finding, Scan.name).join(Scan, Scan.id == Finding.scan_id).where(
        Finding.severity == "Critical")
        .order_by(Finding.last_seen.desc()).limit(8)).all()
    active = []
    for s in session.exec(select(Scan).where(Scan.status.in_(["running", "paused"]))
                          .order_by(Scan.id.desc()).limit(8)).all():
        jc = dict(session.exec(select(Job.status, func.count()).where(
            Job.scan_id == s.id, Job.run_no == s.run_no).group_by(Job.status)).all())
        done = jc.get("done", 0) + jc.get("failed", 0) + jc.get("cancelled", 0)
        active.append({"id": s.id, "name": s.name, "status": s.status, "jobs_done": done,
                       "jobs_total": sum(jc.values())})
    trend = [{"date": str(d), "count": c} for d, c in session.exec(
        select(func.date(Finding.first_seen), func.count()).where(Finding.first_seen >= now - timedelta(days=14))
        .group_by(func.date(Finding.first_seen))).all()]
    acts = session.exec(select(Activity).order_by(Activity.id.desc()).limit(8)).all()
    upcoming = session.exec(select(Scheduler).where(Scheduler.enabled == True)  # noqa: E712
                            .order_by(Scheduler.next_run_at).limit(5)).all()
    return {"scans_total": sum(scans_by_status.values()), "scans_by_status": scans_by_status,
            "active_scans_count": scans_by_status.get("running", 0) + scans_by_status.get("paused", 0),
            "findings_open": sum(by_sev.values()), "findings_by_severity": by_sev,
            "findings_new": findings_new, "findings_removed": removed_last_runs,
            "scanners_total": len(runners), "scanners_connected": sum(1 for r in runners if _connected(r)),
            "slots_total": slots_total, "slots_busy": slots_busy,
            "recent_criticals": [{"id": f.id, "scan_id": f.scan_id, "scan": n, "target": f.target,
                                  "title": f.title, "url": f.url} for f, n in crits],
            "active_scans": active, "trend": trend,
            "upcoming": [{"id": x.id, "name": x.name, "next_run_at": x.next_run_at, "scan_id": x.scan_id}
                         for x in upcoming],
            "recent_activity": [{"kind": a.kind, "message": a.message, "severity": a.severity,
                                 "scan_id": a.scan_id, "at": a.at} for a in acts]}


@router.get("/activity")
def activity_feed(scan_id: int | None = None, kind: str | None = None, limit: int = 50, offset: int = 0,
                  session: Session = Depends(get_session)):
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    base, cnt = select(Activity), select(func.count()).select_from(Activity)
    if scan_id is not None:
        base, cnt = base.where(Activity.scan_id == scan_id), cnt.where(Activity.scan_id == scan_id)
    if kind:
        base, cnt = base.where(Activity.kind == kind), cnt.where(Activity.kind == kind)
    total = session.exec(cnt).one()
    rows = session.exec(base.order_by(Activity.id.desc()).offset(offset).limit(limit)).all()
    return {"items": [{"id": a.id, "at": a.at, "kind": a.kind, "message": a.message, "scan_id": a.scan_id,
                       "runner_id": a.runner_id, "severity": a.severity} for a in rows],
            "total": total, "limit": limit, "offset": offset}

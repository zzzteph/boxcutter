"""Scans: create (now or on a schedule), progress per pipeline stage, targets, findings, assets, live log."""
from __future__ import annotations

import asyncio
import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import case, delete, func, or_, update
from sqlmodel import Session, select

from ..activity import log_activity
from ..db import engine, get_session
from ..models import Activity, Finding, Job, JobEvent, Scan, ScanItem, Scheduler, Target, Template
from ..pipeline import INPUTS, SEED, PlanError
from ..cron import CronError, describe as describe_cron, validate as validate_cron
from ..queue import (enqueue_entry_stages, fire_scheduler, load_plan, maybe_finish_scan, next_run, on_scan_done,
                     start_run)

router = APIRouter(prefix="/scans", tags=["scans"])

_CHUNK = 1000


def ingest_targets(session: Session, scan_id: int, lines, seen: set | None = None) -> int:
    """Stream raw target lines into the scan's own targets: strip, skip blanks and ``#`` comments, de-dupe
    (case-insensitive, trailing ``/.`` ignored), bulk-insert in chunks. Returns the count inserted."""
    seen = seen if seen is not None else set()
    batch: list[dict] = []
    n = 0
    for raw in lines:
        v = str(raw).strip()[:1024]
        if not v or v.startswith("#"):
            continue
        key = v.lower().rstrip("/.")
        if key in seen:
            continue
        seen.add(key)
        batch.append({"scan_id": scan_id, "value": v, "stage": SEED, "key": "", "args_json": ""})
        if len(batch) >= _CHUNK:
            session.bulk_insert_mappings(Target, batch)
            session.commit()
            n += len(batch)
            batch = []
    if batch:
        session.bulk_insert_mappings(Target, batch)
        session.commit()
        n += len(batch)
    return n


def _existing_keys(session: Session, scan_id: int) -> set:
    return {v.lower().rstrip("/.") for v in session.exec(select(Target.value).where(
        Target.scan_id == scan_id, Target.stage == SEED)).all() if v}


def _vars(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        v = json.loads(raw) if raw else {}
        return v if isinstance(v, dict) else {}
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "vars must be valid JSON")


class ScanIn(BaseModel):
    name: str = ""
    template_id: int
    targets: list[str] = []
    vars: dict | None = None             # {custom: [{flag, value}]}
    cron: str | None = None              # set -> create a scheduler that re-runs this on that cron schedule
    timezone: str = "UTC"                # IANA zone the cron is evaluated in
    start_now: bool = True               # with cron: also run it right now (else wait for the first tick)


def _default_name(tmpl: Template, first_target: str) -> str:
    t = (first_target or "").strip()
    return f"{tmpl.title or tmpl.name} — {t}" if t else (tmpl.title or tmpl.name)


def _create(session: Session, name: str, tmpl: Template, lines, vars_: dict,
            cron: str | None, tz: str, start_now: bool) -> dict:
    lines = list(lines)
    first = next((ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")), "")
    name = (name or "").strip() or _default_name(tmpl, first)
    if not first:
        raise HTTPException(400, "add at least one target")
    if cron:
        try:
            expr = validate_cron(cron, tz)
        except CronError as e:
            raise HTTPException(400, str(e))
        sch = Scheduler(name=name, template_id=tmpl.id, targets_text="\n".join(lines), cron=expr, timezone=tz,
                        vars_json=json.dumps(vars_), enabled=True)
        sch.next_run_at = next_run(sch)
        session.add(sch)
        session.commit()
        session.refresh(sch)
        log_activity(session, "scheduler_created", f"Scheduler '{name}' created ({describe_cron(expr)})")
        jobs = fire_scheduler(session, sch) if start_now else 0
        return {"id": sch.scan_id, "scheduler_id": sch.id, "jobs": jobs}
    scan = Scan(name=name[:255], template_id=tmpl.id, template_name=tmpl.title or tmpl.name, status="queued",
                vars_json=json.dumps(vars_))
    session.add(scan)
    session.commit()
    session.refresh(scan)
    n_targets = ingest_targets(session, scan.id, lines)
    try:
        jobs = start_run(session, scan)
    except PlanError as e:
        raise HTTPException(400, str(e))
    log_activity(session, "scan_created", f"Scan '{scan.name}' started — {n_targets} target(s), {jobs} job(s)",
                 scan_id=scan.id)
    return {"id": scan.id, "scheduler_id": None, "jobs": jobs}


def _template_or_404(session: Session, tid: int) -> Template:
    t = session.get(Template, tid)
    if not t:
        raise HTTPException(404, "template not found")
    return t


@router.post("")
def create_scan(body: ScanIn, session: Session = Depends(get_session)):
    tmpl = _template_or_404(session, body.template_id)
    return _create(session, body.name, tmpl, body.targets, body.vars or {}, body.cron, body.timezone, body.start_now)


@router.post("/upload")
def create_scan_upload(template_id: int = Form(...), name: str = Form(""), vars: str | None = Form(None),
                       cron: str | None = Form(None), timezone_: str = Form("UTC", alias="timezone"),
                       start_now: bool = Form(True),
                       file: UploadFile = File(...), session: Session = Depends(get_session)):
    """Create a scan whose targets come from an uploaded file (one per line) - for very large lists."""
    tmpl = _template_or_404(session, template_id)
    text = io.TextIOWrapper(file.file, encoding="utf-8", errors="replace")
    return _create(session, name, tmpl, text, _vars(vars), cron, timezone_, start_now)


# ---- list / detail ------------------------------------------------------------------------------------------
def _summary(session: Session, s: Scan) -> dict:
    counts = {"new": 0, "open": 0, "unconfirmed": 0}
    total_f = 0
    for state, c in session.exec(select(Finding.state, func.count()).where(
            Finding.scan_id == s.id).group_by(Finding.state)).all():
        total_f += c
        counts[state if state in counts else "open"] += c
    sev = dict(session.exec(select(Finding.severity, func.count()).where(
        Finding.scan_id == s.id).group_by(Finding.severity)).all())
    jstat = dict(session.exec(select(Job.status, func.count()).where(
        Job.scan_id == s.id, Job.run_no == s.run_no).group_by(Job.status)).all())
    assets = session.exec(select(func.count()).select_from(Target).where(
        Target.scan_id == s.id, Target.stage == SEED)).one()
    items_total = session.exec(select(func.count()).select_from(ScanItem).where(ScanItem.scan_id == s.id)).one()
    plan = load_plan(s)
    return {"id": s.id, "name": s.name, "status": s.status, "run_no": s.run_no, "template_id": s.template_id,
            "template": s.template_name, "scheduler_id": s.scheduler_id, "assets": assets,
            "steps": len(plan), "distributed": len(plan) > 1,
            "findings_new": counts["new"], "findings_open_state": counts["open"],
            "findings_unconfirmed": counts["unconfirmed"], "removed_last_run": s.removed_last_run,
            "findings_open": total_f,
            "findings_total": total_f, "findings_by_severity": sev, "items_total": items_total,
            "jobs_total": sum(jstat.values()),
            "jobs_done": jstat.get("done", 0) + jstat.get("failed", 0) + jstat.get("cancelled", 0),
            "jobs_failed": jstat.get("failed", 0),
            "running": jstat.get("running", 0) + jstat.get("claimed", 0),
            "created_at": s.created_at, "last_run_at": s.last_run_at, "finished_at": s.finished_at}


@router.get("")
def list_scans(q: str | None = None, status: str | None = None, limit: int = 50, offset: int = 0,
               session: Session = Depends(get_session)):
    limit, offset = _clamp(limit, offset)
    base, count_stmt = select(Scan), select(func.count()).select_from(Scan)
    if q:
        cond = or_(Scan.name.ilike(f"%{q}%"), Scan.template_name.ilike(f"%{q}%"))
        base, count_stmt = base.where(cond), count_stmt.where(cond)
    if status:
        base, count_stmt = base.where(Scan.status == status), count_stmt.where(Scan.status == status)
    total = session.exec(count_stmt).one()
    rows = session.exec(base.order_by(Scan.id.desc()).offset(offset).limit(limit)).all()
    return {"items": [_summary(session, s) for s in rows], "total": total, "limit": limit, "offset": offset}


def _stages(session: Session, scan: Scan) -> list[dict]:
    """The plan of the current run with per-stage progress and a state: waiting | running | done | skipped."""
    plan = load_plan(scan)
    if not plan:
        return []
    jobs: dict[int, dict] = {}
    for st, status, c in session.exec(select(Job.stage, Job.status, func.count()).where(
            Job.scan_id == scan.id, Job.run_no == scan.run_no).group_by(Job.stage, Job.status)).all():
        jobs.setdefault(st, {})[status] = c
    items = dict(session.exec(select(ScanItem.stage, func.count()).where(
        ScanItem.scan_id == scan.id, ScanItem.run_no == scan.run_no).group_by(ScanItem.stage)).all())
    found = dict(session.exec(select(Finding.stage, func.count()).where(
        Finding.scan_id == scan.id).group_by(Finding.stage)).all())
    done_state: dict[int, bool] = {}
    live = scan.status in ("running", "paused")

    def unfinished(i: int) -> int:
        d = jobs.get(i, {})
        return d.get("pending", 0) + d.get("claimed", 0) + d.get("running", 0)

    def is_done(i: int) -> bool:
        if i not in done_state:
            done_state[i] = (unfinished(i) == 0 and all(is_done(p) for p in plan[i].get("from", []) if p != SEED))
        return done_state[i]

    out = []
    for i, st in enumerate(plan):
        d = jobs.get(i, {})
        total = sum(d.values())
        if not live and scan.status != "done":
            state = "stopped" if total and unfinished(i) else ("done" if total else "skipped")
        elif is_done(i):
            state = "done" if total else ("skipped" if (live or scan.status == "done") else "waiting")
        elif total:
            state = "running"
        else:
            state = "waiting"
        out.append({"index": i, "title": st.get("title") or st.get("template"), "template": st.get("template"),
                    "kind": st.get("kind"), "from": st.get("from", []), "input": st.get("input", "all"),
                    "input_label": INPUTS.get(st.get("input", "all"), st.get("input")), "args": st.get("args", ""),
                    "produces": st.get("produces", ""), "state": state,
                    "jobs": {"total": total, "done": d.get("done", 0), "failed": d.get("failed", 0),
                             "cancelled": d.get("cancelled", 0), "pending": d.get("pending", 0),
                             "running": d.get("running", 0) + d.get("claimed", 0)},
                    "items": items.get(i, 0), "findings": found.get(i, 0),
                    "description": st.get("description", "")})
    return out


@router.get("/{scan_id}")
def get_scan(scan_id: int, session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    out = _summary(session, scan)
    targets = list(session.exec(select(Target.value).where(
        Target.scan_id == scan_id, Target.stage == SEED).limit(200)).all())
    try:
        vars_ = json.loads(scan.vars_json or "{}") or {}
    except Exception:  # noqa: BLE001
        vars_ = {}
    tmpl = session.get(Template, scan.template_id) if scan.template_id else None
    sch = session.get(Scheduler, scan.scheduler_id) if scan.scheduler_id else None
    out.update({"targets": targets, "vars": vars_, "stages": _stages(session, scan),
                "template_info": ({"id": tmpl.id, "title": tmpl.title or tmpl.name, "kind": tmpl.kind,
                                   "builtin": tmpl.builtin, "description": tmpl.description} if tmpl else None),
                "scheduler": ({"id": sch.id, "name": sch.name, "cron": sch.cron, "timezone": sch.timezone,
                               "schedule": describe_cron(sch.cron), "enabled": sch.enabled,
                               "next_run_at": sch.next_run_at} if sch else None)})
    return out


def _scan_or_404(session: Session, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    return scan


class ScanPatch(BaseModel):
    name: str | None = None


@router.patch("/{scan_id}")
def update_scan(scan_id: int, body: ScanPatch, session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    if body.name is not None and body.name.strip():
        scan.name = body.name.strip()[:255]
    session.add(scan)
    session.commit()
    return get_scan(scan_id, session)


def _delete_rows(session: Session, model, scan_id: int, batch: int = 5000) -> None:
    """Delete one child table's rows of a scan in bounded batches (never one giant transaction)."""
    while session.exec(select(model.id).where(model.scan_id == scan_id).limit(1)).first() is not None:
        sub = select(model.id).where(model.scan_id == scan_id).limit(batch)
        session.execute(delete(model).where(model.id.in_(sub)))
        session.commit()


@router.delete("/{scan_id}")
def delete_scan(scan_id: int, session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    name = scan.name
    scan.status = "stopped"                    # stop claims + let agents drop in-flight jobs during the delete
    session.add(scan)
    session.commit()
    for model in (Finding, ScanItem, JobEvent, Job, Target, Activity):
        _delete_rows(session, model, scan_id)
    for sch in session.exec(select(Scheduler).where(Scheduler.scan_id == scan_id)).all():
        sch.scan_id = None                     # the scheduler starts a fresh scan on its next run
        session.add(sch)
    session.delete(scan)
    session.commit()
    log_activity(session, "scan_deleted", f"Scan '{name}' deleted")
    return {"ok": True}


_TRUNCATE = {"findings": [Finding], "items": [ScanItem], "all": [Finding, ScanItem]}


@router.post("/{scan_id}/truncate")
def truncate_scan(scan_id: int, scope: str = "findings", session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    models = _TRUNCATE.get(scope)
    if not models:
        raise HTTPException(400, f"scope must be one of: {', '.join(_TRUNCATE)}")
    for m in models:
        _delete_rows(session, m, scan_id)
    log_activity(session, "scan_truncated", f"Cleared {scope} on '{scan.name}'", scan_id=scan_id)
    return {"ok": True}


# ---- run control --------------------------------------------------------------------------------------------
@router.post("/{scan_id}/pause")
def pause(scan_id: int, session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    if scan.status == "running":
        scan.status = "paused"
        session.add(scan)
        session.commit()
        log_activity(session, "scan_paused", f"Scan '{scan.name}' paused", scan_id=scan_id, severity="warn")
    return {"ok": True, "status": scan.status}


@router.post("/{scan_id}/resume")
def resume(scan_id: int, session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    if scan.status == "paused":
        scan.status = "running"
        session.add(scan)
        session.commit()
        log_activity(session, "scan_resumed", f"Scan '{scan.name}' resumed", scan_id=scan_id)
        if maybe_finish_scan(session, scan_id):
            on_scan_done(session, scan)
    return {"ok": True, "status": scan.status}


@router.post("/{scan_id}/stop")
def stop(scan_id: int, session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    scan.status = "stopped"
    scan.finished_at = datetime.now(timezone.utc)
    session.add(scan)
    session.execute(update(Job).where(Job.scan_id == scan_id, Job.status.in_(["pending", "claimed", "running"]))
                    .values(status="cancelled"))
    session.commit()
    log_activity(session, "scan_stopped", f"Scan '{scan.name}' stopped", scan_id=scan_id, severity="warn")
    return {"ok": True, "status": scan.status}


@router.post("/{scan_id}/rerun")
def rerun(scan_id: int, session: Session = Depends(get_session)):
    """Run the scan again (a new run; findings diff against the previous one). Uses the template as it is
    now, so edits to a pipeline take effect."""
    scan = _scan_or_404(session, scan_id)
    try:
        jobs = start_run(session, scan)
    except PlanError as e:
        raise HTTPException(400, str(e))
    log_activity(session, "scan_rerun", f"Scan '{scan.name}' run #{scan.run_no} started ({jobs} jobs)",
                 scan_id=scan_id)
    return {"ok": True, "status": scan.status, "run_no": scan.run_no, "jobs": jobs}


# ---- targets ------------------------------------------------------------------------------------------------
_MAX_ADD = 50000


class TargetsIn(BaseModel):
    targets: list[str] = []


class TargetIds(BaseModel):
    ids: list[int] = []


def _clamp(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(limit, 500)), max(0, offset)


@router.get("/{scan_id}/targets")
def list_targets(scan_id: int, q: str | None = None, stage: int = SEED, limit: int = 100, offset: int = 0,
                 session: Session = Depends(get_session)):
    """The scan's own targets (stage=-1, default) or what was fanned out into pipeline stage N."""
    _scan_or_404(session, scan_id)
    limit, offset = _clamp(limit, offset)
    conds = [Target.scan_id == scan_id, Target.stage == stage]
    if q:
        conds.append(Target.value.ilike(f"%{q}%"))
    total = session.exec(select(func.count()).select_from(Target).where(*conds)).one()
    rows = session.exec(select(Target).where(*conds).order_by(Target.id).offset(offset).limit(limit)).all()
    return {"items": [{"id": t.id, "value": t.value} for t in rows], "total": total, "limit": limit,
            "offset": offset}


def _add(session: Session, scan: Scan, lines) -> dict:
    added = ingest_targets(session, scan.id, lines, seen=_existing_keys(session, scan.id))
    jobs = 0
    if added:
        if scan.status in ("done", "stopped", "queued"):
            scan.status, scan.finished_at = "running", None
            session.add(scan)
            session.commit()
        jobs = enqueue_entry_stages(session, scan)
        log_activity(session, "targets_added", f"Added {added} target(s) to '{scan.name}' ({jobs} jobs)",
                     scan_id=scan.id)
        sch = session.get(Scheduler, scan.scheduler_id) if scan.scheduler_id else None
        if sch is not None:                    # keep the scheduler's list in sync
            vals = session.exec(select(Target.value).where(Target.scan_id == scan.id, Target.stage == SEED)).all()
            sch.targets_text = "\n".join(vals)
            session.add(sch)
            session.commit()
    return {"added": added, "jobs": jobs}


@router.post("/{scan_id}/targets")
def add_targets(scan_id: int, body: TargetsIn, session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    if len(body.targets) > _MAX_ADD:
        raise HTTPException(413, f"too many targets in one call (max {_MAX_ADD}); upload a file instead")
    return _add(session, scan, body.targets)


@router.post("/{scan_id}/targets/upload")
def add_targets_upload(scan_id: int, file: UploadFile = File(...), session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    return _add(session, scan, io.TextIOWrapper(file.file, encoding="utf-8", errors="replace"))


@router.post("/{scan_id}/targets/delete")
def remove_targets(scan_id: int, body: TargetIds, session: Session = Depends(get_session)):
    _scan_or_404(session, scan_id)
    ids = body.ids[:10000]
    if ids:
        session.execute(update(Job).where(Job.scan_id == scan_id, Job.target_id.in_(ids),
                                          Job.status.in_(["pending", "claimed", "running"]))
                        .values(status="cancelled"))
        session.execute(delete(Target).where(Target.scan_id == scan_id, Target.id.in_(ids),
                                             Target.stage == SEED))
        session.commit()
        if maybe_finish_scan(session, scan_id):
            on_scan_done(session, session.get(Scan, scan_id))
    return {"removed": len(ids)}


# ---- findings -----------------------------------------------------------------------------------------------
_SEV_RANK = ["Critical", "High", "Medium", "Low", "Info"]
_FINDING_SORTS = {"title": Finding.title, "target": Finding.target, "state": Finding.state,
                  "last_seen": Finding.last_seen}


def _finding_conds(scan_id, state, severity, target, q, stage=None):
    conds = [Finding.scan_id == scan_id]
    if stage is not None:
        conds.append(Finding.stage == stage)
    if state in ("new", "open", "unconfirmed"):
        conds.append(Finding.state == state)
    if severity:
        conds.append(Finding.severity == severity)
    if target:
        conds.append(Finding.target == target)
    if q:
        like = f"%{q}%"
        conds.append(or_(Finding.title.ilike(like), Finding.target.ilike(like),
                         Finding.url.ilike(like), Finding.cls.ilike(like)))
    return conds


def _finding_order(sort, dir):
    col = _FINDING_SORTS.get(sort)
    if col is None:
        col = case(*[(Finding.severity == s, i) for i, s in enumerate(_SEV_RANK)], else_=len(_SEV_RANK))
    return col.desc() if dir == "desc" else col.asc()


@router.get("/{scan_id}/findings")
def scan_findings(scan_id: int, state: str | None = None, severity: str | None = None, target: str | None = None,
                  q: str | None = None, stage: int | None = None, sort: str = "severity", dir: str = "asc",
                  limit: int = 50, offset: int = 0, session: Session = Depends(get_session)):
    _scan_or_404(session, scan_id)
    limit, offset = _clamp(limit, offset)
    conds = _finding_conds(scan_id, state, severity, target, q, stage)
    total = session.exec(select(func.count()).select_from(Finding).where(*conds)).one()
    rows = session.exec(select(Finding).where(*conds).order_by(_finding_order(sort, dir), Finding.id.desc())
                        .offset(offset).limit(limit)).all()
    items = [{"id": f.id, "target": f.target, "severity": f.severity, "title": f.title, "url": f.url,
              "cls": f.cls, "state": f.state, "template_kind": f.template_kind, "first_seen": f.first_seen,
              "last_seen": f.last_seen} for f in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


_EXPORT_COLS = ["severity", "title", "target", "url", "cls", "state", "first_seen", "last_seen",
                "evidence", "reproduce"]


@router.get("/{scan_id}/findings/export")
def findings_export(scan_id: int, format: str = "csv", state: str | None = None, severity: str | None = None,
                    target: str | None = None, q: str | None = None, sort: str = "severity", dir: str = "asc",
                    session: Session = Depends(get_session)):
    _scan_or_404(session, scan_id)
    conds = _finding_conds(scan_id, state, severity, target, q)
    order = (_finding_order(sort, dir), Finding.id.desc())
    if format == "json":
        rows = session.exec(select(Finding).where(*conds).order_by(*order)).all()
        payload = json.dumps([{c: getattr(f, c) for c in _EXPORT_COLS} for f in rows], default=str, indent=2)
        return Response(payload, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-findings.json"'})

    def _rows():
        head = io.StringIO()
        csv.writer(head).writerow(_EXPORT_COLS)
        yield head.getvalue()
        offset, batch = 0, 5000
        while True:
            chunk = session.exec(select(Finding).where(*conds).order_by(*order).offset(offset).limit(batch)).all()
            if not chunk:
                break
            buf = io.StringIO()
            w = csv.writer(buf)
            for f in chunk:
                w.writerow([getattr(f, c) for c in _EXPORT_COLS])
            yield buf.getvalue()
            if len(chunk) < batch:
                break
            offset += batch
    return StreamingResponse(_rows(), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-findings.csv"'})


@router.get("/{scan_id}/findings/{finding_id}")
def scan_finding_detail(scan_id: int, finding_id: int, session: Session = Depends(get_session)):
    f = session.get(Finding, finding_id)
    if not f or f.scan_id != scan_id:
        raise HTTPException(404)
    try:
        raw = json.loads(f.raw_json) if f.raw_json else {}
    except Exception:  # noqa: BLE001
        raw = {}
    return {"id": f.id, "evidence": f.evidence, "reproduce": f.reproduce, "raw": raw, "cls": f.cls,
            "template_kind": f.template_kind, "url": f.url, "first_seen": f.first_seen, "last_seen": f.last_seen,
            "severity": f.severity, "title": f.title, "target": f.target, "state": f.state,
            "fingerprint": f.fingerprint}


# ---- items (discovered assets) ------------------------------------------------------------------------------
_ITEM_SORTS = {"value": ScanItem.value, "target": ScanItem.target, "last_seen": ScanItem.last_seen,
               "first_seen": ScanItem.first_seen}


def _item_conds(scan_id, target, q, asset_type=None, stage=None):
    conds = [ScanItem.scan_id == scan_id]
    if target:
        conds.append(ScanItem.target == target)
    if asset_type:
        conds.append(ScanItem.asset_type == asset_type)
    if stage is not None:
        conds.append(ScanItem.stage == stage)
    if q:
        like = f"%{q}%"
        conds.append(or_(ScanItem.value.ilike(like), ScanItem.label.ilike(like), ScanItem.target.ilike(like)))
    return conds


def _item_order(sort, dir):
    col = _ITEM_SORTS.get(sort, ScanItem.value)
    return col.desc() if dir == "desc" else col.asc()


@router.get("/{scan_id}/items")
def scan_items(scan_id: int, target: str | None = None, q: str | None = None, type: str | None = None,
               stage: int | None = None, sort: str = "value", dir: str = "asc", limit: int = 100,
               offset: int = 0, session: Session = Depends(get_session)):
    _scan_or_404(session, scan_id)
    limit, offset = _clamp(limit, offset)
    base = _item_conds(scan_id, target, q, stage=stage)
    counts = {t: 0 for t in ("domain", "subdomain", "url", "ip", "endpoint", "other")}
    for atype, c in session.exec(select(ScanItem.asset_type, func.count()).where(*base)
                                 .group_by(ScanItem.asset_type)).all():
        k = atype if atype in counts else "other"
        counts[k] += c
    conds = _item_conds(scan_id, target, q, type, stage)
    total = session.exec(select(func.count()).select_from(ScanItem).where(*conds)).one()
    rows = session.exec(select(ScanItem).where(*conds).order_by(_item_order(sort, dir), ScanItem.id)
                        .offset(offset).limit(limit)).all()
    return {"items": [{"id": i.id, "value": i.value, "label": i.label, "target": i.target, "cls": i.cls,
                       "stage": i.stage, "asset_type": i.asset_type or "other", "first_seen": i.first_seen,
                       "last_seen": i.last_seen} for i in rows],
            "total": total, "counts": counts, "limit": limit, "offset": offset}


@router.get("/{scan_id}/items/export")
def items_export(scan_id: int, target: str | None = None, q: str | None = None, type: str | None = None,
                 stage: int | None = None, sort: str = "value", dir: str = "asc",
                 session: Session = Depends(get_session)):
    _scan_or_404(session, scan_id)
    rows = session.exec(select(ScanItem.value).where(*_item_conds(scan_id, target, q, type, stage))
                        .order_by(_item_order(sort, dir), ScanItem.id).limit(200_000)).all()
    body = "\n".join(v for v in rows if v)
    return Response(body + ("\n" if body else ""), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-items.txt"'})


# ---- report -------------------------------------------------------------------------------------------------
_SEV_ORDER = {s: i for i, s in enumerate(_SEV_RANK)}


@router.get("/{scan_id}/report")
def scan_report(scan_id: int, session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    findings = session.exec(select(Finding).where(Finding.scan_id == scan.id)).all()
    active = findings
    by_sev: dict = {}
    for f in active:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    sev_summary = ", ".join(f"{by_sev[s]} {s}" for s in sorted(by_sev, key=lambda x: _SEV_ORDER.get(x, 9))) or "none"
    out = [f"# Scan report — {scan.name}", "",
           f"- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
           f"- Status: {scan.status} (run #{scan.run_no})",
           f"- Scan type: {scan.template_name}",
           f"- Findings: {len(active)} ({scan.removed_last_run} no longer found in the last run and removed)",
           f"- Open by severity: {sev_summary}", "", "## Findings"]
    for f in sorted(active, key=lambda x: (_SEV_ORDER.get(x.severity, 9), x.target)):
        out += ["", f"### [{f.severity}] {f.title or '(untitled)'}", f"- Target: {f.target}"]
        if f.url:
            out.append(f"- URL: {f.url}")
        if f.cls:
            out.append(f"- Class: {f.cls}")
        out.append(f"- State: {f.state}")
        if f.evidence:
            out.append(f"- Evidence:\n\n```\n{f.evidence}\n```")
        if f.reproduce:
            out.append(f"- Reproduce:\n\n```\n{f.reproduce}\n```")
    if not active:
        out.append("\n_No open findings._")
    return PlainTextResponse("\n".join(out) + "\n", media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.md"'})


# ---- jobs + live log ----------------------------------------------------------------------------------------
_JOB_RANK = {"running": 0, "claimed": 1, "pending": 2, "failed": 3, "done": 4, "cancelled": 5}


@router.get("/{scan_id}/jobs")
def scan_jobs(scan_id: int, status: str | None = None, q: str | None = None, stage: int | None = None,
              limit: int = 50, offset: int = 0, session: Session = Depends(get_session)):
    scan = _scan_or_404(session, scan_id)
    limit, offset = _clamp(limit, offset)
    plan = load_plan(scan)
    base = [Job.scan_id == scan_id, Job.run_no == scan.run_no]
    if stage is not None:
        base.append(Job.stage == stage)
    counts = dict(session.exec(select(Job.status, func.count()).where(*base).group_by(Job.status)).all())
    stmt = select(Job, Target.value).join(Target, Target.id == Job.target_id).where(*base)
    if status:
        stmt = stmt.where(Job.status == status)
    if q:
        stmt = stmt.where(Target.value.ilike(f"%{q}%"))
    total = session.exec(select(func.count()).select_from(stmt.subquery())).one()
    order = case(*[(Job.status == s, r) for s, r in _JOB_RANK.items()], else_=9)
    rows = session.exec(stmt.order_by(order, Job.id).offset(offset).limit(limit)).all()
    items = []
    for j, value in rows:
        argv = json.loads(j.argv_json or "[]")
        dur = round((j.finished_at - j.claimed_at).total_seconds(), 1) if (j.claimed_at and j.finished_at) else None
        step = plan[j.stage] if 0 <= j.stage < len(plan) else {}
        items.append({"id": j.id, "target": value, "status": j.status, "stage": j.stage,
                      "step": step.get("title", ""), "runner_id": j.runner_id, "attempts": j.attempts,
                      "command": ("boxcutter " + " ".join(argv)) if argv else "", "error": j.error,
                      "output": j.output, "claimed_at": j.claimed_at, "finished_at": j.finished_at,
                      "duration_sec": dur})
    return {"items": items, "total": total, "counts": counts, "limit": limit, "offset": offset}


@router.get("/{scan_id}/events")
def scan_events(scan_id: int, since: int = 0, tail: int = 0, job_id: int | None = None, stage: int | None = None,
                session: Session = Depends(get_session)):
    _scan_or_404(session, scan_id)
    conds = [JobEvent.scan_id == scan_id]
    if job_id is not None:
        conds.append(JobEvent.job_id == job_id)
    if stage is not None:                      # one workflow step's log, across all its jobs
        conds.append(JobEvent.job_id.in_(select(Job.id).where(Job.scan_id == scan_id, Job.stage == stage)))
    if tail and tail > 0:
        rows = list(reversed(session.exec(select(JobEvent).where(*conds)
                                          .order_by(JobEvent.id.desc()).limit(min(tail, 1000))).all()))
    else:
        rows = session.exec(select(JobEvent).where(*conds, JobEvent.id > since)
                            .order_by(JobEvent.id).limit(500)).all()
    return [{"cursor": e.id, "job_id": e.job_id, "phase": e.phase, "agent": e.agent, "line": e.line, "at": e.at}
            for e in rows]


async def _sse(scan_id: int, since: int):
    cursor = since
    yield "retry: 3000\n\n"
    while True:
        with Session(engine) as s:
            rows = s.exec(select(JobEvent).where(JobEvent.scan_id == scan_id, JobEvent.id > cursor)
                          .order_by(JobEvent.id).limit(300)).all()
            batch = [{"cursor": e.id, "job_id": e.job_id, "phase": e.phase, "agent": e.agent, "line": e.line}
                     for e in rows]
        if batch:
            cursor = batch[-1]["cursor"]
            for e in batch:
                yield f"data: {json.dumps(e)}\n\n"
        else:
            yield ": keepalive\n\n"
        await asyncio.sleep(1.0)


@router.get("/{scan_id}/stream")
async def scan_stream(scan_id: int, since: int = 0, session: Session = Depends(get_session)):
    _scan_or_404(session, scan_id)
    return StreamingResponse(_sse(scan_id, since), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

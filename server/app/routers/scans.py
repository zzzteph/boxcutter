from __future__ import annotations

import asyncio
import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import case, delete, func, or_, update
from sqlmodel import Session, select

from ..activity import log_activity
from ..db import engine, get_session
from ..models import (Activity, Finding, Job, JobEvent, Scan, ScanItem, Target, Template, User)
from ..queue import enqueue_scan
from ..security import current_user, decode_user

router = APIRouter(prefix="/scans", tags=["scans"])

MAX_TARGETS = 100_000        # hard cap on targets per scan (protects the import path and response sizes)


class ScanIn(BaseModel):
    name: str
    template_id: int
    targets: list[str]
    vars: dict | None = None          # scan-specific inputs (esp. for ai_agent): {context, creds, custom:[{key,value}]}
    authorized: bool = False


class ScanPatch(BaseModel):
    name: str | None = None
    vars: dict | None = None


def _perm(session: Session, scan: Scan, user: User):
    # single shared group: any authenticated user can view and act on any scan
    return "write"


def _require_write(session, scan, user):
    return  # everyone can act (single shared group)


def _summary(session: Session, s: Scan) -> dict:
    # All counts are aggregate queries — never load the finding/job/target rows (a scan can have 100k+ of each).
    counts = {"new": 0, "open": 0, "resolved": 0}
    total_f = 0
    for state, c in session.exec(select(Finding.state, func.count()).where(
            Finding.scan_id == s.id).group_by(Finding.state)).all():
        total_f += c
        counts[state if state in counts else "open"] += c
    jstat = dict(session.exec(select(Job.status, func.count()).where(
        Job.scan_id == s.id, Job.run_no == s.run_no).group_by(Job.status)).all())
    jobs_total = sum(jstat.values())
    jobs_done = jstat.get("done", 0) + jstat.get("failed", 0) + jstat.get("cancelled", 0)
    running = jstat.get("running", 0) + jstat.get("claimed", 0)
    running_targets: list[str] = []
    if running:
        for tid in session.exec(select(Job.target_id).where(
                Job.scan_id == s.id, Job.run_no == s.run_no,
                Job.status.in_(["claimed", "running"])).limit(6)).all():
            t = session.get(Target, tid)
            if t:
                running_targets.append(t.value)
    assets = session.exec(select(func.count()).select_from(Target).where(Target.scan_id == s.id)).one()
    # non-finding results (a recon workflow's domain list, a crawl's URLs). 0 hides the Items panel entirely.
    items_total = session.exec(select(func.count()).select_from(ScanItem).where(ScanItem.scan_id == s.id)).one()
    return {"id": s.id, "name": s.name, "status": s.status, "run_no": s.run_no,
            "template_id": s.template_id, "owner_id": s.owner_id, "assets": assets,
            "findings_new": counts["new"], "findings_open_state": counts["open"],
            "findings_resolved": counts["resolved"],
            "findings_open": counts["new"] + counts["open"],   # "active" = new + open
            "findings_total": total_f,
            "items_total": items_total,
            "jobs_total": jobs_total, "jobs_done": jobs_done,
            "running": running, "running_targets": running_targets,
            "created_at": s.created_at, "last_run_at": s.last_run_at, "finished_at": s.finished_at}


@router.post("")
def create_scan(body: ScanIn, user: User = Depends(current_user), session: Session = Depends(get_session)):
    if not session.get(Template, body.template_id):
        raise HTTPException(404, "template not found")
    now = datetime.now(timezone.utc)
    scan = Scan(name=body.name, owner_id=user.id, template_id=body.template_id, status="running",
                run_no=1, vars_json=json.dumps(body.vars or {}), authorized_ack_at=now, last_run_at=now)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    # de-dupe the import (case-insensitive, ignoring a trailing slash/dot), cap, and bulk-insert in chunks —
    # importing 20k+ domains stays fast; keep each target's first-seen original spelling.
    seen: set[str] = set()
    values: list[str] = []
    for t in body.targets:
        v = t.strip()[:1024]
        if not v:
            continue
        key = v.lower().rstrip("/.")
        if key in seen:
            continue
        seen.add(key)
        values.append(v)
        if len(values) >= MAX_TARGETS:
            break
    tmaps = [{"scan_id": scan.id, "value": v} for v in values]
    for i in range(0, len(tmaps), 1000):
        session.bulk_insert_mappings(Target, tmaps[i:i + 1000])
    session.commit()
    n = enqueue_scan(session, scan)
    log_activity(session, "scan_created", f"Scan '{scan.name}' created — {n} assets", scan_id=scan.id)
    return {"id": scan.id, "jobs": n}


@router.get("")
def list_scans(q: str | None = None, limit: int = 50, offset: int = 0,
               user: User = Depends(current_user), session: Session = Depends(get_session)):
    limit, offset = _clamp(limit, offset)
    base, count_stmt = select(Scan), select(func.count()).select_from(Scan)
    if q:
        base = base.where(Scan.name.ilike(f"%{q}%"))
        count_stmt = count_stmt.where(Scan.name.ilike(f"%{q}%"))
    total = session.exec(count_stmt).one()
    rows = session.exec(base.order_by(Scan.id.desc()).offset(offset).limit(limit)).all()
    return {"items": [_summary(session, s) for s in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}")
def get_scan(scan_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404, "not found")
    # cap the returned target list (a scan can have tens of thousands; the UI lists assets via /jobs, paginated)
    targets = list(session.exec(select(Target.value).where(
        Target.scan_id == scan_id).limit(500)).all())
    jstat = dict(session.exec(select(Job.status, func.count()).where(
        Job.scan_id == scan_id).group_by(Job.status)).all())
    out = _summary(session, scan)
    try:
        vars_ = json.loads(scan.vars_json or "{}") or {}
    except Exception:
        vars_ = {}
    tmpl = session.get(Template, scan.template_id)
    out.update({"targets": targets, "jobs": jstat, "vars": vars_,
                "template": ({"id": tmpl.id, "name": tmpl.name, "kind": tmpl.kind, "context": tmpl.context,
                              "spec": json.loads(tmpl.spec_json or "{}")} if tmpl else None)})
    return out


@router.patch("/{scan_id}")
def update_scan(scan_id: int, body: ScanPatch, user: User = Depends(current_user),
                session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404, "not found")
    if body.name is not None:
        scan.name = body.name
    if body.vars is not None:
        scan.vars_json = json.dumps(body.vars)
    session.add(scan)
    session.commit()
    log_activity(session, "scan_updated", f"Scan '{scan.name}' inputs updated", scan_id=scan.id)
    return get_scan(scan_id, user, session)


def _delete_scan_rows(session: Session, model, scan_id: int, batch: int = 5000) -> None:
    """Delete a scan's rows for one child table in bounded batches, committing between each. A scan can own
    millions of findings/jobs/events; doing it in ONE transaction would hold the SQLite write lock (and grow
    the WAL) long enough to stall every claim/heartbeat — i.e. the server would appear to hang. Batching frees
    the lock repeatedly so the rest of the app keeps serving. Portable (no DELETE ... LIMIT): delete the ids
    from a bounded sub-select, loop until none remain."""
    while session.exec(select(model.id).where(model.scan_id == scan_id).limit(1)).first() is not None:
        sub = select(model.id).where(model.scan_id == scan_id).limit(batch)
        session.execute(delete(model).where(model.id.in_(sub)))
        session.commit()


@router.delete("/{scan_id}")
def delete_scan(scan_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    """Delete a scan and everything it owns. Batched, children first so no foreign key dangles, and the scan is
    marked non-claimable up front so no new work is claimed (and in-flight agents drop it) while we delete."""
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404, "not found")
    name = scan.name
    scan.status = "stopped"                    # stop new claims + let agents drop in-flight jobs during delete
    session.add(scan)
    session.commit()
    for model in (Finding, ScanItem, JobEvent, Job, Target, Activity):
        _delete_scan_rows(session, model, scan_id)
    session.delete(scan)
    session.commit()
    log_activity(session, "scan_deleted", f"Scan '{name}' deleted")     # scan_id omitted — the row is gone
    return {"ok": True}


_SEV_RANK = ["Critical", "High", "Medium", "Low", "Info"]


def _sev_case():
    """SQL ordering expression so 'Critical' sorts before 'High' before ... regardless of DB."""
    return case(*[(Finding.severity == s, i) for i, s in enumerate(_SEV_RANK)], else_=len(_SEV_RANK))


def _clamp(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(limit, 200)), max(0, offset)


_FINDING_SORTS = {"severity": None, "title": Finding.title, "target": Finding.target,
                  "state": Finding.state, "last_seen": Finding.last_seen}


def _finding_conds(scan_id, state, severity, target, q):
    conds = [Finding.scan_id == scan_id]
    if state == "active":
        conds.append(Finding.state != "resolved")
    elif state in ("new", "open", "resolved"):
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
    col = _FINDING_SORTS.get(sort) if sort in _FINDING_SORTS else None
    if col is None:                                  # severity uses the Critical->Info rank
        col = _sev_case()
    return col.desc() if dir == "desc" else col.asc()


@router.get("/{scan_id}/findings")
def scan_findings(scan_id: int, state: str | None = None, severity: str | None = None,
                  target: str | None = None, q: str | None = None, sort: str = "severity",
                  dir: str = "asc", limit: int = 50, offset: int = 0, user: User = Depends(current_user),
                  session: Session = Depends(get_session)):
    """Findings with server-side filter (state/severity/target/search), sort, and pagination — built for scans
    with thousands of findings. Returns {items, total, limit, offset}."""
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404)
    limit, offset = _clamp(limit, offset)
    conds = _finding_conds(scan_id, state, severity, target, q)
    total = session.exec(select(func.count()).select_from(Finding).where(*conds)).one()
    rows = session.exec(select(Finding).where(*conds).order_by(_finding_order(sort, dir), Finding.id.desc())
                        .offset(offset).limit(limit)).all()
    # LIST is intentionally light — no evidence/reproduce/raw (those can be many KB each). The table only shows
    # them when a row is expanded, so the UI fetches the detail then (GET .../findings/{id}). This keeps the
    # list small and cheap to poll for a live scan.
    items = [{"id": f.id, "target": f.target, "severity": f.severity, "title": f.title, "url": f.url,
              "cls": f.cls, "state": f.state, "fingerprint": f.fingerprint, "template_kind": f.template_kind,
              "first_seen": f.first_seen, "last_seen": f.last_seen} for f in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


# ---- items: the non-finding results (a recon workflow's domains, a crawl's URLs) ---------------------------
_ITEM_SORTS = {"value": ScanItem.value, "target": ScanItem.target, "last_seen": ScanItem.last_seen,
               "first_seen": ScanItem.first_seen}


def _item_conds(scan_id, target, q):
    conds = [ScanItem.scan_id == scan_id]
    if target:
        conds.append(ScanItem.target == target)
    if q:
        like = f"%{q}%"
        conds.append(or_(ScanItem.value.ilike(like), ScanItem.label.ilike(like), ScanItem.target.ilike(like)))
    return conds


def _item_order(sort, dir):
    col = _ITEM_SORTS.get(sort, ScanItem.value)
    return col.desc() if dir == "desc" else col.asc()


@router.get("/{scan_id}/items")
def scan_items(scan_id: int, target: str | None = None, q: str | None = None, sort: str = "value",
               dir: str = "asc", limit: int = 100, offset: int = 0, user: User = Depends(current_user),
               session: Session = Depends(get_session)):
    """The scan's non-finding results, filtered/sorted/paged like the findings table. Same shape:
    {items, total, limit, offset}."""
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404)
    limit, offset = _clamp(limit, offset)
    conds = _item_conds(scan_id, target, q)
    total = session.exec(select(func.count()).select_from(ScanItem).where(*conds)).one()
    rows = session.exec(select(ScanItem).where(*conds).order_by(_item_order(sort, dir), ScanItem.id.asc())
                        .offset(offset).limit(limit)).all()
    return {"items": [{"id": i.id, "value": i.value, "label": i.label, "target": i.target, "cls": i.cls,
                       "first_seen": i.first_seen, "last_seen": i.last_seen} for i in rows],
            "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}/items/export")
def items_export(scan_id: int, target: str | None = None, q: str | None = None, sort: str = "value",
                 dir: str = "asc", user: User = Depends(current_user),
                 session: Session = Depends(get_session)):
    """Download the filtered items as plain text, ONE PER LINE — the format you can pipe straight back into a
    tool. Honours the same filters/sort as the list; up to 100k lines."""
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404)
    rows = session.exec(select(ScanItem.value).where(*_item_conds(scan_id, target, q))
                        .order_by(_item_order(sort, dir), ScanItem.id.asc()).limit(100_000)).all()
    body = "\n".join(v for v in rows if v)
    return Response(body + ("\n" if body else ""), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-items.txt"'})


_EXPORT_COLS = ["severity", "title", "target", "url", "cls", "state", "first_seen", "last_seen",
                "evidence", "reproduce"]


@router.get("/{scan_id}/findings/export")
def findings_export(scan_id: int, format: str = "csv", state: str | None = None, severity: str | None = None,
                    target: str | None = None, q: str | None = None, sort: str = "severity", dir: str = "asc",
                    user: User = Depends(current_user), session: Session = Depends(get_session)):
    """Download the filtered findings as CSV or JSON (honours the same filters/sort as the table; up to 10k)."""
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404)
    conds = _finding_conds(scan_id, state, severity, target, q)
    rows = session.exec(select(Finding).where(*conds)
                        .order_by(_finding_order(sort, dir), Finding.id.desc()).limit(10000)).all()
    if format == "json":
        payload = json.dumps([{c: getattr(f, c) for c in _EXPORT_COLS} for f in rows], default=str, indent=2)
        return Response(payload, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-findings.json"'})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_EXPORT_COLS)
    for f in rows:
        w.writerow([getattr(f, c) for c in _EXPORT_COLS])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-findings.csv"'})


@router.get("/{scan_id}/findings/{finding_id}")
def scan_finding_detail(scan_id: int, finding_id: int, user: User = Depends(current_user),
                        session: Session = Depends(get_session)):
    """The heavy per-finding detail (evidence, reproduce, full raw report) — fetched on demand when a finding
    row is expanded, so the findings LIST stays light. (Defined after /export so that literal route wins.)"""
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404)
    f = session.get(Finding, finding_id)
    if not f or f.scan_id != scan_id:
        raise HTTPException(404)
    try:
        raw = json.loads(f.raw_json) if f.raw_json else {}
    except Exception:  # noqa: BLE001
        raw = {}
    return {"id": f.id, "evidence": f.evidence, "reproduce": f.reproduce, "raw": raw, "cls": f.cls,
            "template_kind": f.template_kind, "url": f.url, "first_seen": f.first_seen, "last_seen": f.last_seen}


_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _build_report(session: Session, scan: Scan) -> str:
    """A single markdown report: an executive summary + the open findings, ordered by severity."""
    findings = session.exec(select(Finding).where(Finding.scan_id == scan.id)).all()
    tmpl = session.get(Template, scan.template_id)
    active = [f for f in findings if f.state != "resolved"]
    by_sev: dict = {}
    for f in active:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev_summary = ", ".join(f"{by_sev[s]} {s}" for s in sorted(by_sev, key=lambda x: _SEV_ORDER.get(x, 9))) or "none"
    crit, high = by_sev.get("Critical", 0), by_sev.get("High", 0)

    out = [f"# Scan report — {scan.name}", "",
           f"- Generated: {now}",
           f"- Status: {scan.status} (run #{scan.run_no})"]
    if tmpl:
        out.append(f"- Template: {tmpl.name} ({tmpl.kind})")
    out += [f"- Findings: {len(active)} open, {len(findings) - len(active)} resolved",
            f"- Open by severity: {sev_summary}", "", "## Executive summary"]
    if crit or high:
        out.append(f"This scan surfaced **{crit} critical** and **{high} high**-severity findings that warrant "
                   "prompt attention.")
    elif active:
        out.append("No critical or high-severity findings; the open items are lower-risk or informational.")
    else:
        out.append("No open findings.")
    out += ["", "## Findings"]
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
    return "\n".join(out) + "\n"


@router.get("/{scan_id}/report")
def scan_report(scan_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404)
    return PlainTextResponse(_build_report(session, scan), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-report.md"'})


_JOB_STATUS_RANK = {"running": 0, "claimed": 1, "pending": 2, "failed": 3, "done": 4, "cancelled": 5}


@router.get("/{scan_id}/jobs")
def scan_jobs(scan_id: int, status: str | None = None, q: str | None = None, run: int | None = None,
              limit: int = 50, offset: int = 0, user: User = Depends(current_user),
              session: Session = Depends(get_session)):
    """Per-asset debug/state for a run (default the current run): exact command, status, runner, attempts,
    error, raw output. Returns {items, total, counts, limit, offset} - `counts` is per-status for progress."""
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404)
    limit, offset = _clamp(limit, offset)
    run_no = run if run is not None else scan.run_no
    counts = dict(session.exec(select(Job.status, func.count()).where(
        Job.scan_id == scan_id, Job.run_no == run_no).group_by(Job.status)).all())

    stmt = select(Job, Target.value).join(Target, Target.id == Job.target_id).where(
        Job.scan_id == scan_id, Job.run_no == run_no)
    if status:
        stmt = stmt.where(Job.status == status)
    if q:
        stmt = stmt.where(Target.value.ilike(f"%{q}%"))
    total = sum(counts.values()) if not (status or q) else \
        session.exec(select(func.count()).select_from(stmt.subquery())).one()
    order = case(*[(Job.status == s, r) for s, r in _JOB_STATUS_RANK.items()], else_=9)
    rows = session.exec(stmt.order_by(order, Job.id).offset(offset).limit(limit)).all()

    items = []
    for j, target_value in rows:
        argv = json.loads(j.argv_json or "[]")
        dur = round((j.finished_at - j.claimed_at).total_seconds(), 1) if (j.claimed_at and j.finished_at) else None
        items.append({"id": j.id, "target": target_value, "status": j.status, "run_no": j.run_no,
                      "runner_id": j.runner_id, "attempts": j.attempts,
                      "command": ("boxcutter " + " ".join(argv)) if argv else "", "error": j.error,
                      "output": j.output, "claimed_at": j.claimed_at, "finished_at": j.finished_at,
                      "duration_sec": dur})
    return {"items": items, "total": total, "counts": counts, "limit": limit, "offset": offset}


@router.get("/{scan_id}/events")
def scan_events(scan_id: int, since: int = 0, tail: int = 0, user: User = Depends(current_user),
                session: Session = Depends(get_session)):
    """Live-log events. `since` streams forward from a cursor (the poll fallback). `tail=N` returns only the
    most RECENT N events — the page seeds with this so opening a scan with a huge backlog doesn't replay the
    whole history (it then streams only new events from the newest id)."""
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404)
    if tail and tail > 0:
        rows = session.exec(select(JobEvent).where(JobEvent.scan_id == scan_id)
                            .order_by(JobEvent.id.desc()).limit(min(tail, 1000))).all()
        rows = list(reversed(rows))                  # newest N, returned oldest-first for display
    else:
        rows = session.exec(select(JobEvent).where(
            JobEvent.scan_id == scan_id, JobEvent.id > since).order_by(JobEvent.id).limit(500)).all()
    return [{"cursor": e.id, "job_id": e.job_id, "phase": e.phase, "agent": e.agent,
             "line": e.line, "reasoning": e.reasoning, "at": e.at} for e in rows]


def _sse_user(access_token: str = Query(default=""), authorization: str = Header(default=""),
              session: Session = Depends(get_session)) -> User:
    """Auth for the SSE stream: EventSource can't set headers, so accept the JWT as ?access_token= too."""
    token = access_token or (authorization.split(" ", 1)[1]
                             if authorization.lower().startswith("bearer ") else "")
    user = decode_user(token, session) if token else None
    if not user:
        raise HTTPException(401, "invalid token")
    return user


async def sse_event_gen(scan_id: int, since: int):
    """Yield SSE frames for a scan's JobEvents as they land (incl. per-agent reasoning). Each tick uses a fresh
    short-lived session and never holds one across the await. Runs until the client disconnects."""
    cursor = since
    yield "retry: 3000\n\n"
    while True:
        with Session(engine) as s:
            rows = s.exec(select(JobEvent).where(
                JobEvent.scan_id == scan_id, JobEvent.id > cursor).order_by(JobEvent.id).limit(300)).all()
            batch = [{"cursor": e.id, "job_id": e.job_id, "phase": e.phase, "agent": e.agent,
                      "line": e.line, "reasoning": e.reasoning} for e in rows]
        if batch:
            cursor = batch[-1]["cursor"]
            for e in batch:
                yield f"data: {json.dumps(e)}\n\n"
        else:
            yield ": keepalive\n\n"
        await asyncio.sleep(1.0)


@router.get("/{scan_id}/stream")
async def scan_stream(scan_id: int, since: int = 0, user: User = Depends(_sse_user),
                      session: Session = Depends(get_session)):
    """Server-sent events for the live log: pushes JobEvent lines (incl. per-agent reasoning) as they land.
    Single-process, DB-backed (no broker). The client falls back to GET /events polling if this drops."""
    scan = session.get(Scan, scan_id)
    if not scan or not _perm(session, scan, user):
        raise HTTPException(404)
    return StreamingResponse(sse_event_gen(scan_id, since), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                                      "Connection": "keep-alive"})


def _set_status(scan_id, new, user, session, cancel_pending=False, bump_run=False):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404)
    _require_write(session, scan, user)
    if bump_run:
        scan.run_no += 1
        scan.last_run_at = datetime.now(timezone.utc)
        scan.finished_at = None
    scan.status = new
    session.add(scan)
    if cancel_pending:
        # Stop cancels ALL unfinished work — pending AND in-flight (claimed/running). Set-based so it stays fast
        # for a 100k-job scan. The agent learns its in-flight jobs are cancelled on its next heartbeat and kills
        # the running boxcutter subprocesses (see runners._jobs_to_cancel).
        session.execute(update(Job).where(
            Job.scan_id == scan_id, Job.status.in_(["pending", "claimed", "running"])).values(status="cancelled"))
    session.commit()
    jobs = enqueue_scan(session, scan) if bump_run else 0
    if bump_run:
        kind, verb, sev = "scan_rerun", f"rerun (run #{scan.run_no}, {jobs} assets)", "info"
    elif new == "paused":
        kind, verb, sev = "scan_paused", "paused", "warn"
    elif new == "stopped":
        kind, verb, sev = "scan_stopped", "stopped", "warn"
    else:
        kind, verb, sev = "scan_resumed", "resumed", "info"
    log_activity(session, kind, f"Scan '{scan.name}' {verb}", scan_id=scan_id, severity=sev)
    return {"ok": True, "status": scan.status, "run_no": scan.run_no, "jobs": jobs}


@router.post("/{scan_id}/pause")
def pause(scan_id: int, user=Depends(current_user), session=Depends(get_session)):
    return _set_status(scan_id, "paused", user, session)


@router.post("/{scan_id}/resume")
def resume(scan_id: int, user=Depends(current_user), session=Depends(get_session)):
    return _set_status(scan_id, "running", user, session)


@router.post("/{scan_id}/stop")
def stop(scan_id: int, user=Depends(current_user), session=Depends(get_session)):
    return _set_status(scan_id, "stopped", user, session, cancel_pending=True)


@router.post("/{scan_id}/rerun")
def rerun(scan_id: int, user=Depends(current_user), session=Depends(get_session)):
    return _set_status(scan_id, "running", user, session, bump_run=True)

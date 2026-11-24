"""The scanner-agent protocol (token auth, not basic auth).

An agent enrolls once with an enroll token to get its own runner token, then claims jobs, streams live log
lines, posts results and heartbeats. A result's non-finding items are handed straight to the pipeline engine,
which fans them out to the next stage(s) as new jobs."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..activity import log_activity
from ..config import settings
from ..db import get_session
from ..diff import is_issue, item_value, upsert_finding, upsert_item
from ..models import EnrollToken, Job, JobEvent, Runner, Scan, Target
from ..notify import notify_findings
from ..pipeline import expand, stage_argv
from ..queue import claim_job, load_plan, maybe_finish_scan, on_scan_done, promote_items
from ..security import current_runner, hash_token

router = APIRouter(prefix="/runner", tags=["runner"])


class EnrollIn(BaseModel):
    token: str = ""
    name: str = "runner"
    host: str = ""
    ip: str = ""
    version: str = ""
    engine_version: str = ""
    slots: int = 1
    internal: bool = False                # the server's built-in agent enrolls with this


@router.post("/enroll")
def enroll(body: EnrollIn, session: Session = Depends(get_session)):
    et = session.exec(select(EnrollToken).where(
        EnrollToken.token_hash == hash_token(body.token or ""), EnrollToken.revoked == False)).first()  # noqa: E712
    if not body.token or et is None:
        raise HTTPException(401, "enrollment rejected")
    token = secrets.token_urlsafe(32)
    # the built-in agent is a singleton: re-enrolling reuses its row instead of piling up duplicates
    runner = session.exec(select(Runner).where(Runner.internal == True)).first() if body.internal else None  # noqa: E712
    if runner is None:
        runner = Runner(internal=body.internal)
    runner.name, runner.host, runner.ip, runner.version = body.name, body.host, body.ip, body.version
    runner.engine_version = body.engine_version or runner.engine_version
    runner.slots, runner.token_hash = body.slots, hash_token(token)
    runner.last_heartbeat = datetime.now(timezone.utc)
    session.add(runner)
    session.commit()
    session.refresh(runner)
    log_activity(session, "scanner_enrolled", f"Scanner '{runner.name}' enrolled"
                 + (f" ({runner.ip})" if runner.ip else ""), runner_id=runner.id)
    return {"runner_id": runner.id, "runner_token": token}


@router.post("/claim")
def claim(runner: Runner = Depends(current_runner), session: Session = Depends(get_session)):
    job = claim_job(session, runner)
    if not job:
        return {"job": None}
    scan = session.get(Scan, job.scan_id)
    target = session.get(Target, job.target_id)
    plan = load_plan(scan) if scan else []
    if scan is None or target is None or not (0 <= job.stage < len(plan)):
        job.status, job.error = "failed", "scan/target/stage no longer exists"
        session.add(job)
        session.commit()
        return {"job": None}
    try:
        vars_ = json.loads(scan.vars_json or "{}") or {}
    except Exception:  # noqa: BLE001
        vars_ = {}
    try:
        targs = json.loads(target.args_json) if target.args_json else []
    except Exception:  # noqa: BLE001
        targs = []
    argv = stage_argv(plan[job.stage], target.value, targs, vars_)
    job.argv_json = json.dumps(argv)
    session.add(job)
    session.commit()
    log_activity(session, "job_claimed", f"'{runner.name}' took {target.value}",
                 scan_id=job.scan_id, runner_id=runner.id)
    return {"job": {"id": job.id, "scan_id": job.scan_id, "target": target.value, "argv": argv,
                    "token": job.token}, "secrets": {}}


def _stale(job: Job | None, runner: Runner, token: str) -> bool:
    """Drop a post for a job that is gone, belongs to another runner, or whose run token no longer matches."""
    if not job or job.runner_id != runner.id:
        return True
    return bool(job.token and token and token != job.token)


class EventIn(BaseModel):
    phase: str = ""
    agent: str = ""
    line: str = ""
    token: str = ""


@router.post("/jobs/{job_id}/event")
def job_event(job_id: int, body: EventIn, runner: Runner = Depends(current_runner),
              session: Session = Depends(get_session)):
    job = session.get(Job, job_id)
    if _stale(job, runner, body.token):
        raise HTTPException(404)
    if job.status == "claimed":
        job.status = "running"
        session.add(job)
    line = body.line or ""
    if line.startswith("[[bc:step "):          # engine box markers (only meaningful to the old canvas)
        session.commit()
        return {"ok": True}
    session.add(JobEvent(job_id=job_id, scan_id=job.scan_id, phase=body.phase[:64], agent=body.agent[:64],
                         line=line[:4000]))
    session.commit()
    return {"ok": True}


class ResultIn(BaseModel):
    envelope: dict = {}
    report: str | None = None
    error: str | None = None
    token: str = ""
    assets: list = []                  # accepted for older agents; ignored


@router.post("/jobs/{job_id}/result")
def job_result(job_id: int, body: ResultIn, runner: Runner = Depends(current_runner),
               session: Session = Depends(get_session)):
    job = session.get(Job, job_id)
    if _stale(job, runner, body.token):
        raise HTTPException(404)
    if job.status in ("cancelled", "done", "failed"):     # already resolved (stopped/deleted/reassigned)
        return {"ok": True, "ignored": True}
    scan = session.get(Scan, job.scan_id)
    target = session.get(Target, job.target_id)
    if scan is None or target is None:
        return {"ok": True, "ignored": True}
    plan = load_plan(scan)
    stage = plan[job.stage] if 0 <= job.stage < len(plan) else {}
    kind = stage.get("kind", "")
    env = body.envelope or {}
    env_kind = str(env.get("kind") or "")
    new_findings: list[dict] = []
    produced: list = []
    for f in env.get("data") or []:
        # a tool that reports findings -> issues; anything else (urls / hosts / request objects) -> items that
        # are listed in the scan's Assets AND flow into the next pipeline stage(s)
        as_finding = (env_kind == "findings") if env_kind else (isinstance(f, dict) and is_issue(f))
        if as_finding and isinstance(f, dict) and is_issue(f):
            _, created = upsert_finding(session, job.scan_id, kind, target.value, f, run_no=job.run_no,
                                        stage=job.stage)
            if created:
                new_findings.append({"severity": str(f.get("severity", "info")).title(),
                                     "title": str(f.get("title", ""))[:200], "url": str(f.get("url", "")),
                                     "target": target.value})
            continue
        for it in expand(f):
            value = item_value(it)
            if not value:
                continue
            produced.append(it)
            upsert_item(session, job.scan_id, kind, target.value, value,
                        label=str(it.get("title", ""))[:400] if isinstance(it, dict) else "",
                        cls=str(it.get("cls", ""))[:120] if isinstance(it, dict) else "",
                        run_no=job.run_no, stage=job.stage)
    session.commit()
    # fan the produced items out BEFORE this job is marked done, so the scan can never look "drained" while
    # its next stage is still being enqueued
    promote_items(session, scan, job.stage, produced)

    if body.error:                                # retry a failed job up to the cap, else mark it failed
        job.status = "pending" if job.attempts < settings.job_max_attempts else "failed"
        if job.status == "pending":
            job.runner_id = None
    else:
        job.status = "done"
    job.error = body.error
    job.output = (body.report or "")[:20000]
    job.finished_at = datetime.now(timezone.utc)
    session.add(job)
    session.commit()

    if body.error:
        if job.status == "pending":
            log_activity(session, "job_retry", f"{target.value} failed — retrying (attempt {job.attempts})",
                         scan_id=job.scan_id, runner_id=runner.id, severity="warn")
        else:
            log_activity(session, "job_failed", f"{target.value} failed after {job.attempts} attempts",
                         scan_id=job.scan_id, runner_id=runner.id, severity="warn")
    for f in new_findings:
        if f["severity"] == "Critical":
            log_activity(session, "new_critical", f"Critical: {f['title']} on {f['target']}",
                         scan_id=job.scan_id, severity="critical")
    if new_findings:
        notify_findings(session, scan.name, new_findings)
    if maybe_finish_scan(session, job.scan_id):
        on_scan_done(session, session.get(Scan, job.scan_id))
    return {"ok": True}


class HeartbeatIn(BaseModel):
    status: str = "idle"
    slots: int = 1
    busy_slots: int = 0
    current_jobs: list[int] = []
    version: str = ""
    engine_version: str = ""
    ip: str = ""
    metrics: dict = {}


@router.post("/heartbeat")
def heartbeat(body: HeartbeatIn, runner: Runner = Depends(current_runner),
              session: Session = Depends(get_session)):
    runner.status = body.status
    runner.slots = body.slots
    runner.busy_slots = body.busy_slots
    runner.current_jobs_json = json.dumps(body.current_jobs)
    runner.metrics_json = json.dumps(body.metrics or {})
    if body.version:
        runner.version = body.version
    if body.engine_version:
        runner.engine_version = body.engine_version
    if body.ip:
        runner.ip = body.ip
    runner.last_heartbeat = datetime.now(timezone.utc)
    if runner.desired_slots is not None and body.slots == runner.desired_slots:
        runner.desired_slots = None               # the agent applied the requested concurrency
    session.add(runner)
    session.commit()
    # tell the agent which running jobs to STOP: scan deleted/stopped, or the job was reassigned/resolved
    cancel = []
    for jid in body.current_jobs or []:
        job = session.get(Job, jid)
        if job is None or job.runner_id != runner.id or job.status not in ("claimed", "running"):
            cancel.append(jid)
            continue
        scan = session.get(Scan, job.scan_id)
        if scan is None or scan.status == "stopped":
            cancel.append(jid)
    return {"ok": True, "desired_slots": runner.desired_slots, "cancel": cancel}

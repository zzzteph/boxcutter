"""Runner-facing endpoints (token auth) + the admin fleet view and enroll-token management.

A runner enrolls once (enroll token or user creds) to get a scoped token, then claims jobs, streams events,
posts results, and heartbeats. The api key for an ai_agent job is delivered here at claim time as a job secret,
never stored on the runner and never logged."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import case, func, or_
from sqlmodel import Session, select

from ..activity import log_activity
from ..config import settings
from ..db import get_session
from ..diff import is_issue, item_value, reconcile_run, upsert_finding, upsert_item
from ..notify import notify, notify_findings
from ..models import (Activity, EnrollToken, Finding, Job, JobEvent, LLMProfile, NotifySettings, Runner, Scan,
                      Target, Template, User)
from ..queue import claim_job, maybe_finish_scan
from ..security import (current_runner, current_user, hash_token, require_admin, user_from_api_key,
                        verify_password)

router = APIRouter(tags=["runners"])

_ENV_FOR = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "litellm": "LITELLM_API_KEY"}


def _kv_to_argv(items, default_prefix="--") -> list:
    """Render a list of {flag/key, value} rows to argv tokens. A row with no value becomes a bare flag
    (boolean); a `key` without a leading dash is prefixed with `--`."""
    out: list = []
    for it in items or []:
        flag = str(it.get("flag") or it.get("key") or "").strip()
        if not flag:
            continue
        if not flag.startswith("-"):
            flag = default_prefix + flag
        out.append(flag)
        val = it.get("value", "")
        if val is not None and str(val) != "":
            out.append(str(val))
    return out


def _spec_params_to_argv(spec: dict) -> list:
    """Template-level boxcutter parameters: the structured spec['params']=[{flag,value}] plus the legacy
    flat spec['flags']=[...] (kept for seeded/older templates and power users)."""
    return _kv_to_argv(spec.get("params", [])) + [str(f) for f in (spec.get("flags", []) or [])]


# per-kind flags that make boxcutter narrate live progress to stderr (see each subcommand's --help)
_PROGRESS_FLAGS = {"tool": ("--debug",), "workflow": ("--steps", "--show-findings")}


def build_argv(session: Session, tmpl: Template, target: str, scan: Scan | None = None):
    """Map a template + target (+ the scan's own inputs) to a boxcutter CLI argv and any secret env it needs.
    All kinds run as `boxcutter <argv>` (the CLI desugars agent/tool/workflow names). Template params are the
    same for every scan that uses the template; the scan's vars (context/creds/custom) are per-scan."""
    spec = json.loads(tmpl.spec_json or "{}")
    name = spec.get("name", "")
    # the engine is `boxcutter <tool> <target>`, `boxcutter workflow <name> <target>`, or
    # `boxcutter ai <agent> <target>` — prefix the right subcommand for the template's kind.
    if tmpl.kind == "workflow":
        argv = ["workflow", name, target]
    elif tmpl.kind == "ai_agent":
        argv = ["ai", name, target]
    else:
        argv = [name, target]
    secrets_env: dict = {}
    vars_: dict = {}
    if scan is not None:
        try:
            vars_ = json.loads(scan.vars_json or "{}") or {}
        except Exception:
            vars_ = {}
    if tmpl.kind == "ai_agent":
        if tmpl.llm_profile_id:
            p = session.get(LLMProfile, tmpl.llm_profile_id)
            if p:
                argv += ["--provider", p.provider]
                if p.model:
                    argv += ["--model", p.model]
                if p.proxy_url:
                    argv += ["--llm-proxy-url", p.proxy_url]
                if p.api_key_secret:
                    secrets_env[_ENV_FOR.get(p.provider, "API_KEY")] = p.api_key_secret
        # a scan may override the template's default context, and add per-engagement credentials
        context = (vars_.get("context") or "").strip() or (tmpl.context or "")
        if context:
            argv += ["--context", context]
        creds = (vars_.get("creds") or "").strip()
        if creds:
            argv += ["--creds", creds]
    argv += _spec_params_to_argv(spec)                       # template-level params
    argv += _kv_to_argv(vars_.get("custom", []))             # scan-specific custom params (any kind)
    # Make the engine narrate its progress to stderr so the live-steps view fills in AS the scan runs. Tools are
    # silent by default (--debug); workflows print each step + finding as it happens (--steps --show-findings);
    # AI agents already stream their own reasoning. All go to stderr, which the runner forwards as live events —
    # the final JSON on stdout (findings / raw output) is unchanged. Skip any flag the template already set.
    for flag in _PROGRESS_FLAGS.get(tmpl.kind, ()):
        if flag not in argv:
            argv.append(flag)
    return argv, secrets_env


# ---- enrollment ---------------------------------------------------------------------------------------------
class EnrollIn(BaseModel):
    token: str | None = None
    api_key: str | None = None            # a system-user (or user) API key may also enroll a runner
    username: str | None = None
    password: str | None = None
    name: str = "runner"
    host: str = ""
    ip: str = ""
    version: str = ""                     # agent (supervisor) version
    engine_version: str = ""              # boxcutter engine version the agent probed
    slots: int = 1
    internal: bool = False                # the all-in-one server's built-in agent enrolls with this


@router.post("/runner/enroll")
def enroll(body: EnrollIn, session: Session = Depends(get_session)):
    ok = False
    if body.token:
        et = session.exec(select(EnrollToken).where(
            EnrollToken.token_hash == hash_token(body.token), EnrollToken.revoked == False)).first()  # noqa: E712
        ok = et is not None
    elif body.api_key:
        ok = user_from_api_key(body.api_key, session) is not None
    elif body.username:
        u = session.exec(select(User).where(User.username == body.username)).first()
        ok = bool(u and verify_password(body.password or "", u.password_hash))
    if not ok:
        raise HTTPException(401, "enrollment rejected")
    token = secrets.token_urlsafe(32)
    # The built-in agent is a permanent SINGLETON: re-enrolling it (e.g. after a server restart that lost the
    # agent's local token) reuses the one internal runner row instead of piling up duplicates that can't be
    # removed. External agents always create a fresh row.
    runner = session.exec(select(Runner).where(Runner.internal == True)).first() if body.internal else None  # noqa: E712
    if runner is not None:
        runner.name, runner.host, runner.ip, runner.version = body.name, body.host, body.ip, body.version
        runner.engine_version = body.engine_version or runner.engine_version
        runner.slots, runner.token_hash = body.slots, hash_token(token)
        runner.last_heartbeat = datetime.now(timezone.utc)
    else:
        runner = Runner(name=body.name, host=body.host, ip=body.ip, version=body.version,
                        engine_version=body.engine_version, slots=body.slots,
                        internal=body.internal, token_hash=hash_token(token),
                        last_heartbeat=datetime.now(timezone.utc))
    session.add(runner)
    session.commit()
    session.refresh(runner)
    log_activity(session, "scanner_enrolled", f"Scanner '{runner.name}' enrolled"
                 + (f" ({runner.ip})" if runner.ip else ""), runner_id=runner.id)
    return {"runner_id": runner.id, "runner_token": token}


# ---- job loop -----------------------------------------------------------------------------------------------
class ClaimIn(BaseModel):
    models: list[str] = []                 # local models the agent has installed (gates ollama-profile jobs)


@router.post("/runner/claim")
def claim(body: ClaimIn = ClaimIn(), runner: Runner = Depends(current_runner),
          session: Session = Depends(get_session)):
    # NEVER hand this runner a job whose required local model it lacks - it simply isn't selected for it.
    job = claim_job(session, runner, body.models)
    if not job:
        return {"job": None}
    tmpl = session.get(Template, job.template_id)
    target = session.get(Target, job.target_id)
    argv, secrets_env = build_argv(session, tmpl, target.value, session.get(Scan, job.scan_id))
    job.argv_json = json.dumps(argv)          # remember the exact command for the debug view
    session.add(job)
    session.commit()
    log_activity(session, "job_claimed", f"'{runner.name}' took {target.value}",
                 scan_id=job.scan_id, runner_id=runner.id)
    return {"job": {"id": job.id, "scan_id": job.scan_id, "target": target.value, "argv": argv,
                    "token": job.token},
            "secrets": secrets_env}


def _stale(job: Job | None, runner: Runner, token: str) -> bool:
    """True if this post should be dropped: the job is gone, belongs to another runner, or its run token no
    longer matches (the integer id was reused by a newer scan after the original was deleted)."""
    if not job or job.runner_id != runner.id:
        return True
    return bool(job.token and token and token != job.token)


class EventIn(BaseModel):
    phase: str = ""
    agent: str = ""
    line: str = ""
    reasoning: str | None = None
    token: str = ""


@router.post("/runner/jobs/{job_id}/event")
def job_event(job_id: int, body: EventIn, runner: Runner = Depends(current_runner),
              session: Session = Depends(get_session)):
    job = session.get(Job, job_id)
    if _stale(job, runner, body.token):
        raise HTTPException(404)
    if job.status == "claimed":
        job.status = "running"
        session.add(job)
    session.add(JobEvent(job_id=job_id, scan_id=job.scan_id, phase=body.phase, agent=body.agent,
                         line=body.line[:4000], reasoning=(body.reasoning or None)))
    session.commit()
    return {"ok": True}


class ResultIn(BaseModel):
    envelope: dict = {}
    report: str | None = None
    error: str | None = None
    token: str = ""


@router.post("/runner/jobs/{job_id}/result")
def job_result(job_id: int, body: ResultIn, runner: Runner = Depends(current_runner),
               session: Session = Depends(get_session)):
    job = session.get(Job, job_id)
    if _stale(job, runner, body.token):
        raise HTTPException(404)
    if job.status in ("cancelled", "done", "failed"):     # already resolved (stopped/deleted/reassigned)
        return {"ok": True, "ignored": True}
    tmpl = session.get(Template, job.template_id)
    target = session.get(Target, job.target_id)
    kind = tmpl.kind if tmpl else ""
    new_crits: list[str] = []
    new_findings: list[dict] = []
    for f in (body.envelope or {}).get("data") or []:
        if isinstance(f, dict) and is_issue(f):
            _, created = upsert_finding(session, job.scan_id, kind, target.value, f, run_no=job.run_no)
            if created:
                sev = str(f.get("severity", "info")).title()
                new_findings.append({"severity": sev, "title": str(f.get("title", ""))[:200],
                                     "url": str(f.get("url", "")), "target": target.value})
                if sev == "Critical":
                    new_crits.append(str(f.get("title", ""))[:200])
            continue
        # Not an issue: a URL/host/endpoint the workflow enumerated, or a bare string in the data list. These
        # used to be dropped — they are kept as scan items so they can be listed and downloaded one per line.
        value = item_value(f)
        if value:
            upsert_item(session, job.scan_id, kind, target.value, value,
                        label=str(f.get("title", ""))[:400] if isinstance(f, dict) else "",
                        cls=str(f.get("cls", ""))[:120] if isinstance(f, dict) else "",
                        run_no=job.run_no)
    if body.error:                                # retry a failed job up to the cap, else mark it failed
        job.status = "pending" if job.attempts < settings.job_max_attempts else "failed"
        job.runner_id = None if job.status == "pending" else job.runner_id
    else:
        job.status = "done"
    job.error = body.error
    job.output = (body.report or "")[:20000]      # raw engine stdout for the debug view
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

    scan = session.get(Scan, job.scan_id)
    for title in new_crits:
        log_activity(session, "new_critical", f"Critical: {title} on {target.value}",
                     scan_id=job.scan_id, severity="critical")
    if new_crits and scan:
        notify("new_critical",
               {"scan_id": scan.id, "scan": scan.name, "count": len(new_crits), "titles": new_crits},
               f"[boxcutter] {len(new_crits)} new critical finding(s) in '{scan.name}'")
    if new_findings:                              # per-finding Telegram alerts (UI-configured, by severity)
        ns = session.get(NotifySettings, 1)
        if ns and ns.telegram_enabled and ns.telegram_token and ns.telegram_chat_id:
            try:
                sevs = set(json.loads(ns.severities_json or "[]"))
            except Exception:  # noqa: BLE001
                sevs = set()
            notify_findings({"token": ns.telegram_token, "chat_id": ns.telegram_chat_id, "severities": sevs},
                            new_findings)
    if maybe_finish_scan(session, job.scan_id):
        scan = session.get(Scan, job.scan_id)
        stats = reconcile_run(session, scan.id, scan.run_no, scan.last_run_at)
        log_activity(session, "scan_done", f"Scan '{scan.name}' done — "
                     f"{stats['new']} new, {stats['open']} open, {stats['resolved']} resolved", scan_id=scan.id)
        notify("scan_done", {"scan_id": scan.id, "scan": scan.name, "run_no": scan.run_no, **stats},
               f"[boxcutter] scan '{scan.name}' done — "
               f"{stats['new']} new, {stats['open']} open, {stats['resolved']} resolved")
    return {"ok": True}


class HeartbeatIn(BaseModel):
    status: str = "idle"
    slots: int = 1
    busy_slots: int = 0
    current_jobs: list[int] = []
    version: str = ""
    engine_version: str = ""           # re-probed by the agent periodically, so an engine update shows up here
    ip: str = ""
    metrics: dict = {}                 # {"cpu": pct, "mem": pct} best-effort from the runner host


@router.post("/runner/heartbeat")
def heartbeat(body: HeartbeatIn, runner: Runner = Depends(current_runner),
              session: Session = Depends(get_session)):
    runner.status = body.status
    runner.slots = body.slots
    runner.busy_slots = body.busy_slots
    runner.current_jobs_json = json.dumps(body.current_jobs)
    runner.metrics_json = json.dumps(body.metrics or {})
    if body.version:
        runner.version = body.version
    if body.engine_version:            # empty = the agent hasn't probed yet; keep the last known answer
        runner.engine_version = body.engine_version
    if body.ip:
        runner.ip = body.ip
    runner.last_heartbeat = datetime.now(timezone.utc)
    # server-requested concurrency: once the agent reports it has applied the value, clear the one-shot command
    if runner.desired_slots is not None and body.slots == runner.desired_slots:
        runner.desired_slots = None
    session.add(runner)
    session.commit()
    # tell the agent which of the jobs it's running should STOP now — the scan was deleted (job gone), stopped
    # (job cancelled), or the job was requeued to someone else. The agent kills those subprocesses and frees
    # the slots, so a deleted/stopped scan doesn't keep scanning and doesn't hold the agent on stale work.
    cancel = _jobs_to_cancel(session, runner, body.current_jobs)
    return {"ok": True, "desired_slots": runner.desired_slots, "cancel": cancel}


def _jobs_to_cancel(session: Session, runner: Runner, current_jobs: list[int]) -> list[int]:
    cancel = []
    for jid in current_jobs or []:
        job = session.get(Job, jid)
        if job is None or job.runner_id != runner.id or job.status not in ("claimed", "running"):
            cancel.append(jid)                       # deleted, reassigned, or already resolved server-side
            continue
        scan = session.get(Scan, job.scan_id)
        if scan is None or scan.status == "stopped":  # paused is graceful (in-flight finishes); stopped is not
            cancel.append(jid)
    return cancel


# ---- fleet (users see it; admin manages enroll tokens) ------------------------------------------------------
def _runner_row(r: Runner) -> dict:
    hb = r.last_heartbeat
    if hb and hb.tzinfo is None:
        hb = hb.replace(tzinfo=timezone.utc)
    connected = hb is not None and hb > (datetime.now(timezone.utc) - timedelta(seconds=45))
    return {"id": r.id, "name": r.name, "host": r.host, "ip": r.ip, "version": r.version,
            "engine_version": r.engine_version, "internal": r.internal,
            "status": r.status if connected else "disconnected", "connected": connected,
            "slots": r.slots, "desired_slots": r.desired_slots, "busy_slots": r.busy_slots,
            "current_jobs": json.loads(r.current_jobs_json or "[]"),
            "metrics": json.loads(r.metrics_json or "{}"),
            "last_heartbeat": r.last_heartbeat, "enrolled_at": r.enrolled_at}


def _job_brief(session: Session, job: Job) -> dict:
    t = session.get(Target, job.target_id)
    tmpl = session.get(Template, job.template_id)
    dur = None
    if job.claimed_at and job.finished_at:
        dur = round((job.finished_at - job.claimed_at).total_seconds(), 1)
    return {"id": job.id, "scan_id": job.scan_id, "target": t.value if t else "",
            "template": tmpl.name if tmpl else "", "status": job.status,
            "claimed_at": job.claimed_at, "finished_at": job.finished_at, "duration_sec": dur}


@router.get("/runners")
def fleet(user: User = Depends(current_user), session: Session = Depends(get_session)):
    return [_runner_row(r) for r in session.exec(select(Runner)).all()]


@router.get("/runners/{runner_id}")
def runner_detail(runner_id: int, user: User = Depends(current_user),
                  session: Session = Depends(get_session)):
    r = session.get(Runner, runner_id)
    if not r:
        raise HTTPException(404)
    row = _runner_row(r)
    current = [_job_brief(session, j) for j in
               (session.get(Job, jid) for jid in row["current_jobs"]) if j]
    last = session.exec(select(Job).where(
        Job.runner_id == runner_id, Job.finished_at != None)  # noqa: E711
        .order_by(Job.finished_at.desc()).limit(12)).all()
    row["current"] = current
    row["last_jobs"] = [_job_brief(session, j) for j in last]
    return row


class RunnerPatch(BaseModel):
    concurrency: int


@router.patch("/runners/{runner_id}")
def set_runner_concurrency(runner_id: int, body: RunnerPatch, admin: User = Depends(require_admin),
                           session: Session = Depends(get_session)):
    """Ask an agent to run more/fewer boxcutters. The agent adopts the value on its next heartbeat (≤10s)."""
    r = session.get(Runner, runner_id)
    if not r:
        raise HTTPException(404)
    r.desired_slots = max(0, min(int(body.concurrency), 32))
    session.add(r)
    session.commit()
    log_activity(session, "runner_concurrency",
                 f"Requested '{r.name or ('runner #' + str(r.id))}' run {r.desired_slots} boxcutter(s)",
                 runner_id=r.id)
    return _runner_row(r)


@router.delete("/runners/{runner_id}")
def delete_runner(runner_id: int, admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    """Remove a scanner from the fleet (e.g. a stale disconnected one). Any jobs it was mid-flight on are
    requeued so another agent picks them up. A still-running agent would simply re-enroll as a new row — stop
    its container (or set its concurrency to 0) to keep it gone."""
    r = session.get(Runner, runner_id)
    if not r:
        raise HTTPException(404)
    if r.internal:
        # the built-in agent is a permanent fixture — set its concurrency to 0 to idle it, but it can't be removed
        raise HTTPException(400, "the built-in agent can't be removed — set its concurrency to 0 to idle it")
    name = r.name or f"runner #{r.id}"
    for job in session.exec(select(Job).where(
            Job.runner_id == runner_id, Job.status.in_(["claimed", "running"]))).all():
        job.status = "pending"
        job.runner_id = None
        session.add(job)
    session.delete(r)
    session.commit()
    log_activity(session, "runner_deleted", f"Scanner '{name}' removed", severity="warn")
    return {"ok": True}


_SEV_RANK = ["Critical", "High", "Medium", "Low", "Info"]


@router.get("/findings")
def global_findings(severity: str | None = None, state: str | None = None, q: str | None = None,
                    scan_id: int | None = None, before: int | None = None, limit: int = 50,
                    user: User = Depends(current_user), session: Session = Depends(get_session)):
    """Findings across ALL scans as a most-recent-first feed with **keyset** pagination (`before` = the last id
    you've seen), so it stays O(page) at any depth — no deep OFFSET over millions of rows. Filter by severity /
    state / search / scan; for 'most severe first', pick a severity. Returns {items, next} (next = the cursor to
    pass as `before` for the following page, or null at the end)."""
    limit = max(1, min(limit, 200))
    conds = []
    if scan_id is not None:
        conds.append(Finding.scan_id == scan_id)
    if state == "active":
        conds.append(Finding.state != "resolved")
    elif state in ("new", "open", "resolved"):
        conds.append(Finding.state == state)
    if severity:
        conds.append(Finding.severity == severity)
    if q:
        like = f"%{q}%"
        conds.append(or_(Finding.title.ilike(like), Finding.target.ilike(like),
                         Finding.url.ilike(like), Finding.cls.ilike(like)))
    if before is not None:
        conds.append(Finding.id < before)      # keyset: only rows older than the last one shown
    stmt = select(Finding, Scan.name).join(Scan, Scan.id == Finding.scan_id)
    if conds:
        stmt = stmt.where(*conds)
    rows = session.exec(stmt.order_by(Finding.id.desc()).limit(limit)).all()
    items = [{"id": f.id, "scan_id": f.scan_id, "scan": name, "severity": f.severity, "title": f.title,
              "target": f.target, "url": f.url, "cls": f.cls, "state": f.state, "last_seen": f.last_seen}
             for f, name in rows]
    nxt = items[-1]["id"] if len(items) == limit else None
    return {"items": items, "next": nxt}


@router.get("/stats")
def stats(user: User = Depends(current_user), session: Session = Depends(get_session)):
    """Overview aggregates for the dashboard: scans/findings/scanners totals, active scans, recent criticals,
    a 14-day new-findings trend, and recent activity."""
    now = datetime.now(timezone.utc)
    scans_by_status = dict(session.exec(select(Scan.status, func.count()).group_by(Scan.status)).all())
    by_sev = dict(session.exec(select(Finding.severity, func.count()).where(
        Finding.state != "resolved").group_by(Finding.severity)).all())
    findings_new = session.exec(select(func.count()).select_from(Finding).where(Finding.state == "new")).one()
    findings_resolved = session.exec(select(func.count()).select_from(Finding).where(
        Finding.state == "resolved")).one()

    cutoff = now - timedelta(seconds=45)
    runners = session.exec(select(Runner)).all()

    def _conn(r):
        hb = r.last_heartbeat
        if hb and hb.tzinfo is None:
            hb = hb.replace(tzinfo=timezone.utc)
        return hb is not None and hb > cutoff
    connected = sum(1 for r in runners if _conn(r))

    scan_names = {s.id: s.name for s in session.exec(select(Scan)).all()}
    crits = session.exec(select(Finding).where(Finding.severity == "Critical", Finding.state != "resolved")
                         .order_by(Finding.last_seen.desc()).limit(8)).all()
    recent_crits = [{"id": f.id, "scan_id": f.scan_id, "scan": scan_names.get(f.scan_id, ""),
                     "target": f.target, "title": f.title, "url": f.url} for f in crits]

    active = []
    for s in session.exec(select(Scan).where(Scan.status.in_(["running", "paused"]))
                          .order_by(Scan.id.desc()).limit(8)).all():
        jc = dict(session.exec(select(Job.status, func.count()).where(
            Job.scan_id == s.id, Job.run_no == s.run_no).group_by(Job.status)).all())
        total = sum(jc.values())
        done = jc.get("done", 0) + jc.get("failed", 0) + jc.get("cancelled", 0)
        active.append({"id": s.id, "name": s.name, "status": s.status, "jobs_done": done, "jobs_total": total})

    since = now - timedelta(days=14)
    trend = [{"date": str(d), "count": c} for d, c in session.exec(
        select(func.date(Finding.first_seen), func.count()).where(Finding.first_seen >= since)
        .group_by(func.date(Finding.first_seen))).all()]
    acts = session.exec(select(Activity).order_by(Activity.id.desc()).limit(8)).all()
    recent_activity = [{"kind": a.kind, "message": a.message, "severity": a.severity,
                        "scan_id": a.scan_id, "at": a.at} for a in acts]

    return {"scans_total": sum(scans_by_status.values()), "scans_by_status": scans_by_status,
            "active_scans_count": scans_by_status.get("running", 0) + scans_by_status.get("paused", 0),
            "findings_open": sum(by_sev.values()), "findings_by_severity": by_sev,
            "findings_new": findings_new, "findings_resolved": findings_resolved,
            "scanners_total": len(runners), "scanners_connected": connected,
            "recent_criticals": recent_crits, "active_scans": active, "trend": trend,
            "recent_activity": recent_activity}


@router.get("/activity")
def activity_feed(scan_id: int | None = None, kind: str | None = None, limit: int = 50, offset: int = 0,
                  user: User = Depends(current_user), session: Session = Depends(get_session)):
    """The clickable activity feed — everything that happened, newest first. Paginated; optional scan_id/kind."""
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


class EnrollTokenIn(BaseModel):
    label: str = ""


@router.post("/enroll-tokens")
def create_enroll_token(body: EnrollTokenIn, admin: User = Depends(require_admin),
                        session: Session = Depends(get_session)):
    token = secrets.token_urlsafe(24)
    session.add(EnrollToken(token_hash=hash_token(token), label=body.label, created_by=admin.id))
    session.commit()
    return {"token": token}     # shown once; only the hash is stored

"""Operator runs: run an ai operator agent (joseph) DIRECTLY on this server and watch its output.

Not a scan - no fleet, no per-target jobs. You pick an LLM profile, give a target + brief, and the engine runs
here as a subprocess (see ..operator). The reasoning streams to a live log the UI polls; the final report +
findings land on the run row. Meant for joseph, the human-operator agent.
"""
from __future__ import annotations

import json
import os
import shutil

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from .. import operator as op
from ..db import get_session
from ..models import LLMProfile, OperatorRun, User
from ..security import current_user

router = APIRouter(prefix="/operator", tags=["operator"])


# ---- Claude Code login status (Request: native claude-code auth in the image) -------------------------------
def _claude_code_login() -> dict:
    """Whether THIS container has an authenticated Claude Code login the `claude-code` provider can ride (no API
    key). Mirrors the engine's discovery: the CLAUDE_CODE_OAUTH_TOKEN env, else the token `claude` writes after
    /login under CLAUDE_CONFIG_DIR (which the image points at the /data volume so it survives restarts)."""
    cfg = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    tok = op.discover_claude_code_token()
    if tok:
        src = ("env CLAUDE_CODE_OAUTH_TOKEN" if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
               else os.path.join(cfg, ".credentials.json"))
        return {"logged_in": True, "source": src}
    return {"logged_in": False, "config_dir": cfg}


@router.get("/claude-code")
def claude_code_status(user: User = Depends(current_user)):
    st = _claude_code_login()
    st["cli_installed"] = bool(shutil.which("claude"))
    st["hint"] = ("Authorize once inside the running container: `docker exec -it <container> claude` then "
                  "`/login`. The login persists on the /data volume (CLAUDE_CONFIG_DIR), so every operator run "
                  "with a claude-code profile uses it - no API key.")
    return st


@router.get("/agents")
def agents(user: User = Depends(current_user)):
    return [{"name": "joseph",
             "help": "Human-operator agent: a live browser + the full tool set + in-container scripting, driven "
                     "by one LLM brain that thinks out loud and acts. Produces a text report."}]


# ---- runs ---------------------------------------------------------------------------------------------------
class RunIn(BaseModel):
    agent: str = "joseph"
    target: str = ""
    context: str = ""                     # the mission brief: goal + endpoints + how to authenticate
    creds: str = ""                       # optional user:pass for a live-browser login
    profile_id: int | None = None
    dry_run: bool = False
    analysts: int = 0                     # parallel read-only analyst lanes (0 = single operator)
    max_steps: int = 40
    authorized: bool = False              # explicit engagement authorization, like a scan's ack


def _row_brief(r: OperatorRun) -> dict:
    vars_ = json.loads(r.vars_json or "{}")
    return {"id": r.id, "agent": r.agent, "target": r.target, "status": r.status,
            "profile_name": r.profile_name, "provider": vars_.get("provider"), "model": vars_.get("model"),
            "created_at": r.created_at, "finished_at": r.finished_at, "live": op.is_live(r.id)}


@router.get("/runs")
def list_runs(user: User = Depends(current_user), session: Session = Depends(get_session)):
    q = select(OperatorRun).order_by(OperatorRun.id.desc())
    if user.role != "admin":
        q = q.where(OperatorRun.owner_id == user.id)
    return [_row_brief(r) for r in session.exec(q.limit(100)).all()]


@router.post("/runs")
def create_run(body: RunIn, user: User = Depends(current_user), session: Session = Depends(get_session)):
    agent = (body.agent or "joseph").strip()
    if agent not in op.ALLOWED_AGENTS:
        raise HTTPException(400, f"unknown operator agent '{agent}'")
    if not body.authorized:
        raise HTTPException(400, "you must confirm you are authorized to test this target")
    target = (body.target or "").strip()
    context = (body.context or "").strip()
    if not target and not context:
        raise HTTPException(400, "give a target, or describe the goal + endpoints in the brief")
    if op.running_count() >= op.MAX_CONCURRENT:
        raise HTTPException(429, f"{op.MAX_CONCURRENT} operator run(s) already in progress on this server - "
                                 "wait for one to finish (or stop it)")

    provider, model, proxy_url, secret_env, profile_name = "anthropic", None, None, {}, ""
    if body.profile_id:
        p = session.get(LLMProfile, body.profile_id)
        if not p:
            raise HTTPException(404, "LLM profile not found")
        provider, model, proxy_url, profile_name = p.provider, p.model, p.proxy_url, p.name
        if p.provider.lower() not in ("claude-code", "ollama") and not p.api_key_secret:
            raise HTTPException(400, f"profile '{p.name}' has no API key set - add one, or use a claude-code / "
                                     "ollama profile")
        if p.api_key_secret:
            secret_env[op._ENV_FOR.get(p.provider.lower(), "API_KEY")] = p.api_key_secret

    analysts = max(0, min(int(body.analysts or 0), 9))
    max_steps = max(1, min(int(body.max_steps or 40), 200))
    vars_ = {"context": context, "creds": bool(body.creds), "dry_run": bool(body.dry_run),
             "analysts": analysts, "max_steps": max_steps, "provider": provider, "model": model}

    row = OperatorRun(owner_id=user.id, agent=agent, target=target, profile_id=body.profile_id,
                      profile_name=profile_name, status="running", vars_json=json.dumps(vars_))
    session.add(row)
    session.commit()
    session.refresh(row)

    opts = {"provider": provider, "model": model, "proxy_url": proxy_url, "context": context,
            "creds": (body.creds or "").strip(), "dry_run": bool(body.dry_run),
            "analysts": analysts, "max_steps": max_steps}
    op.start(row.id, agent, target, opts, secret_env)
    return {"id": row.id}


def _get_owned(session: Session, run_id: int, user: User) -> OperatorRun:
    r = session.get(OperatorRun, run_id)
    if not r or (user.role != "admin" and r.owner_id != user.id):
        raise HTTPException(404, "run not found")
    return r


@router.get("/runs/{run_id}")
def get_run(run_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    r = _get_owned(session, run_id, user)
    return {**_row_brief(r), "vars": json.loads(r.vars_json or "{}"), "report": r.report,
            "findings": json.loads(r.findings_json or "[]"), "meta": json.loads(r.meta_json or "{}"),
            "error": r.error, "exit_code": r.exit_code}


@router.get("/runs/{run_id}/log")
def run_log(run_id: int, since: int = 0, user: User = Depends(current_user),
            session: Session = Depends(get_session)):
    r = _get_owned(session, run_id, user)
    live = op.live_tail(run_id, since)
    if live is not None:
        text, offset, done = live
        return {"text": text, "offset": offset, "done": done, "status": r.status}
    # not in memory (finished, or a prior process): serve the persisted log from the row
    full = r.log or ""
    since = max(0, min(int(since or 0), len(full)))
    return {"text": full[since:], "offset": len(full), "done": True, "status": r.status}


@router.post("/runs/{run_id}/stop")
def stop_run(run_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    r = _get_owned(session, run_id, user)
    if r.status != "running":
        return {"ok": True, "status": r.status}
    r.status = "stopped"                   # mark first so the pump doesn't relabel it 'failed' on the kill
    session.add(r)
    session.commit()
    op.stop(run_id)
    return {"ok": True, "status": "stopped"}


@router.delete("/runs/{run_id}")
def delete_run(run_id: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    r = _get_owned(session, run_id, user)
    if r.status == "running":
        raise HTTPException(409, "stop the run before deleting it")
    ws = os.path.join(op._data_dir(), "operator", str(run_id))
    try:
        shutil.rmtree(ws, ignore_errors=True)
    except Exception:  # noqa: BLE001
        pass
    session.delete(r)
    session.commit()
    return {"ok": True}

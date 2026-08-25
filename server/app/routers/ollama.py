"""Local models: a curated shortlist of small Ollama models with one-click download, and one-click wiring into
an ai_agent LLM profile.

ONE shared Ollama serves everyone: the server pulls/list here, and because an ai_agent profile's proxy_url is
delivered to whatever agent runs the job, every agent does inference against the SAME host. So a model pulled
once is available to all agents - as long as ``settings.ollama_base_url`` is reachable by the server AND the
agents (a routable address, not localhost, on a multi-host deploy).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from .. import ollama as ol
from ..db import get_session
from ..models import LLMProfile, User
from ..security import current_user, require_admin

router = APIRouter(prefix="/ollama", tags=["admin"])


@router.get("/catalog")
def catalog(user: User = Depends(current_user)):
    installed = set(ol.list_installed())
    st = ol.pull_status()
    return {"reachable": ol.reachable(), "base_url": ol.base_url(),
            "models": [{**m, "installed": m["name"] in installed, "pull": st.get(m["name"])}
                       for m in ol.CATALOG]}


class PullIn(BaseModel):
    name: str


@router.post("/pull")
def pull(body: PullIn, admin: User = Depends(require_admin)):
    """Download a catalog model onto the shared Ollama host (background; poll /ollama/status)."""
    try:
        ol.pull_async(body.name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@router.get("/status")
def status(user: User = Depends(current_user)):
    return ol.pull_status()


class WireIn(BaseModel):
    name: str                                  # an ollama model, e.g. qwen2.5:7b


@router.post("/profile")
def make_profile(body: WireIn, admin: User = Depends(require_admin),
                 session: Session = Depends(get_session)):
    """Auto-wire: create (or reuse) an ai_agent-ready LLM profile for a local model - provider ollama, the
    shared OpenAI-compatible base url, no key. It then appears in every ai_agent template's profile picker, and
    every agent that runs it points at the same shared Ollama."""
    pname = f"ollama {body.name}"
    existing = session.exec(select(LLMProfile).where(LLMProfile.name == pname)).first()
    if existing:
        return {"id": existing.id, "name": existing.name, "existed": True}
    p = LLMProfile(name=pname, provider="ollama", model=body.name,
                   proxy_url=ol.openai_base(), api_key_secret="", created_by=admin.id)
    session.add(p)
    session.commit()
    session.refresh(p)
    return {"id": p.id, "name": p.name, "existed": False}

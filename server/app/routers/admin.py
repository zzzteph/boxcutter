"""User administration and LLM profiles. LLM api keys are write-only: created here, delivered only to a runner
at job time, and never returned to any client."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import LLMProfile, NotifySettings, User
from ..notify import telegram_test
from ..security import current_user, hash_password, require_admin

router = APIRouter(tags=["admin"])


class UserIn(BaseModel):
    username: str
    password: str
    role: str = "user"


class UserPatch(BaseModel):
    role: str | None = None
    password: str | None = None


@router.get("/users")
def list_users(admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    return [{"id": u.id, "username": u.username, "role": u.role,
             "must_change_password": u.must_change_password} for u in session.exec(select(User)).all()]


@router.post("/users")
def create_user(body: UserIn, admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    if session.exec(select(User).where(User.username == body.username)).first():
        raise HTTPException(400, "username already exists")
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    session.add(u)
    session.commit()
    session.refresh(u)
    return {"id": u.id, "username": u.username, "role": u.role}


@router.patch("/users/{uid}")
def patch_user(uid: int, body: UserPatch, admin: User = Depends(require_admin),
               session: Session = Depends(get_session)):
    u = session.get(User, uid)
    if not u:
        raise HTTPException(404)
    if body.role:
        u.role = body.role
    if body.password:
        u.password_hash = hash_password(body.password)
        u.must_change_password = True
    session.add(u)
    session.commit()
    return {"ok": True}


@router.delete("/users/{uid}")
def delete_user(uid: int, admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    u = session.get(User, uid)
    if u:
        session.delete(u)
        session.commit()
    return {"ok": True}


# ---- LLM profiles -------------------------------------------------------------------------------------------
class LLMIn(BaseModel):
    name: str
    provider: str
    model: str | None = None
    proxy_url: str | None = None
    api_key: str | None = None


@router.get("/llm-profiles")
def list_llm(user: User = Depends(current_user), session: Session = Depends(get_session)):
    # any user may LIST profiles (to pick one for an ai_agent template); keys are never included
    return [{"id": p.id, "name": p.name, "provider": p.provider, "model": p.model,
             "proxy_url": p.proxy_url, "has_key": bool(p.api_key_secret)}
            for p in session.exec(select(LLMProfile)).all()]


@router.post("/llm-profiles")
def create_llm(body: LLMIn, admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    p = LLMProfile(name=body.name, provider=body.provider, model=body.model, proxy_url=body.proxy_url,
                   api_key_secret=body.api_key or "", created_by=admin.id)
    session.add(p)
    session.commit()
    session.refresh(p)
    return {"id": p.id, "name": p.name}


class LLMPatch(BaseModel):
    model: str | None = None
    proxy_url: str | None = None
    api_key: str | None = None


@router.patch("/llm-profiles/{pid}")
def update_llm(pid: int, body: LLMPatch, admin: User = Depends(require_admin),
               session: Session = Depends(get_session)):
    p = session.get(LLMProfile, pid)
    if not p:
        raise HTTPException(404)
    if body.model is not None:
        p.model = body.model
    if body.proxy_url is not None:
        p.proxy_url = body.proxy_url
    if body.api_key:                      # only overwrite the key when a new one is supplied
        p.api_key_secret = body.api_key
    session.add(p)
    session.commit()
    return {"id": p.id, "name": p.name, "has_key": bool(p.api_key_secret)}


@router.delete("/llm-profiles/{pid}")
def delete_llm(pid: int, admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    p = session.get(LLMProfile, pid)
    if p:
        session.delete(p)
        session.commit()
    return {"ok": True}


# ---- Telegram notifications (admin). Bot token is write-only, never returned to the browser. ----------------
_NOTIFY_SEVS = ["Critical", "High", "Medium", "Low", "Info"]


class TelegramIn(BaseModel):
    enabled: bool | None = None
    chat_id: str | None = None
    token: str | None = None                 # write-only; only stored when a non-empty value is supplied
    severities: list[str] | None = None


def _notify_out(ns: NotifySettings) -> dict:
    try:
        sevs = json.loads(ns.severities_json or "[]")
    except Exception:  # noqa: BLE001
        sevs = []
    return {"enabled": ns.telegram_enabled, "chat_id": ns.telegram_chat_id,
            "has_token": bool(ns.telegram_token), "severities": sevs}


def _get_notify(session: Session) -> NotifySettings:
    ns = session.get(NotifySettings, 1)
    if not ns:
        ns = NotifySettings(id=1)
        session.add(ns)
        session.commit()
    return ns


@router.get("/notify/telegram")
def get_telegram(admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    return _notify_out(_get_notify(session))


@router.post("/notify/telegram")
def set_telegram(body: TelegramIn, admin: User = Depends(require_admin),
                 session: Session = Depends(get_session)):
    ns = _get_notify(session)
    if body.enabled is not None:
        ns.telegram_enabled = body.enabled
    if body.chat_id is not None:
        ns.telegram_chat_id = body.chat_id[:64]
    if body.token:                           # only overwrite the token when a new one is supplied
        ns.telegram_token = body.token
    if body.severities is not None:
        ns.severities_json = json.dumps([s for s in body.severities if s in _NOTIFY_SEVS])
    session.add(ns)
    session.commit()
    return _notify_out(ns)


@router.post("/notify/telegram/test")
def test_telegram(admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    ns = _get_notify(session)
    if not (ns.telegram_token and ns.telegram_chat_id):
        raise HTTPException(400, "set a bot token and chat id first")
    ok, err = telegram_test(ns.telegram_token, ns.telegram_chat_id)
    return {"ok": ok, "error": err}

"""Personal API keys and system (service) users. An API key drives the full REST API without a UI login; a
system user is a REST-API-only account (role=service, no password login) that authenticates only via its key."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import ApiKey, User
from ..security import current_user, hash_password, make_api_key, require_admin

router = APIRouter(tags=["keys"])


def _key_out(k: ApiKey) -> dict:
    return {"id": k.id, "name": k.name, "prefix": k.prefix, "user_id": k.user_id,
            "created_at": k.created_at, "last_used_at": k.last_used_at}


def _issue_key(session: Session, user_id: int, name: str) -> tuple[ApiKey, str]:
    full, prefix, key_hash = make_api_key()
    k = ApiKey(user_id=user_id, name=name or "key", prefix=prefix, key_hash=key_hash)
    session.add(k)
    session.commit()
    session.refresh(k)
    return k, full


class KeyIn(BaseModel):
    name: str = ""


@router.post("/api-keys")
def create_api_key(body: KeyIn, user: User = Depends(current_user), session: Session = Depends(get_session)):
    k, full = _issue_key(session, user.id, body.name)
    return {**_key_out(k), "key": full}         # the full key is returned exactly once


@router.get("/api-keys")
def list_api_keys(user: User = Depends(current_user), session: Session = Depends(get_session)):
    rows = session.exec(select(ApiKey).where(
        ApiKey.user_id == user.id, ApiKey.revoked == False)).all()  # noqa: E712
    return [_key_out(k) for k in rows]


@router.delete("/api-keys/{kid}")
def revoke_api_key(kid: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    k = session.get(ApiKey, kid)
    if not k or (k.user_id != user.id and user.role != "admin"):
        raise HTTPException(403)
    k.revoked = True
    session.add(k)
    session.commit()
    return {"ok": True}


# ---- system (service) users -------------------------------------------------------------------------------
class SystemUserIn(BaseModel):
    username: str
    key_name: str = "default"


@router.post("/system-users")
def create_system_user(body: SystemUserIn, admin: User = Depends(require_admin),
                       session: Session = Depends(get_session)):
    if session.exec(select(User).where(User.username == body.username)).first():
        raise HTTPException(400, "username already exists")
    u = User(username=body.username, password_hash=hash_password(secrets.token_urlsafe(16)), role="service")
    session.add(u)
    session.commit()
    session.refresh(u)
    k, full = _issue_key(session, u.id, body.key_name)
    return {"id": u.id, "username": u.username, "role": u.role, "prefix": k.prefix, "key": full}


@router.post("/users/{uid}/api-keys")
def issue_user_key(uid: int, body: KeyIn, admin: User = Depends(require_admin),
                   session: Session = Depends(get_session)):
    """Admin issues (rotates) a key for any user - handy for system users."""
    u = session.get(User, uid)
    if not u:
        raise HTTPException(404)
    k, full = _issue_key(session, u.id, body.name or "key")
    return {**_key_out(k), "key": full}

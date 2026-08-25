from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import User
from ..security import (current_user, hash_password, make_jwt, new_totp_secret, totp_uri, verify_password,
                        verify_totp)

router = APIRouter(prefix="/auth", tags=["auth"])

# ---- login rate-limiting: blunt brute-force / auth DoS. Per-source sliding window, in-memory (single process;
# each replica limits independently — for a fleet put real rate-limiting at the proxy too). ----
_LOGIN_WINDOW = 300.0        # seconds
_LOGIN_MAX = 10              # failed attempts from one IP within the window before a cooldown
_login_fails: dict[str, list[float]] = {}


def _client_ip(request: Request) -> str:
    return (request.client.host if request.client else "") or "unknown"


def _rate_check(ip: str) -> None:
    now = time.time()
    fails = [t for t in _login_fails.get(ip, []) if now - t < _LOGIN_WINDOW]
    if fails:
        _login_fails[ip] = fails
    else:
        _login_fails.pop(ip, None)
    if len(fails) >= _LOGIN_MAX:
        retry = int(_LOGIN_WINDOW - (now - fails[0])) + 1
        raise HTTPException(429, "too many failed logins — try again later",
                            headers={"Retry-After": str(max(1, retry))})


def _rate_note_fail(ip: str) -> None:
    _login_fails.setdefault(ip, []).append(time.time())


def _rate_clear(ip: str) -> None:
    _login_fails.pop(ip, None)


class LoginIn(BaseModel):
    username: str
    password: str
    code: str | None = None          # TOTP code, required when the account has 2FA enabled


class CodeIn(BaseModel):
    code: str


class ChangePw(BaseModel):
    current_password: str
    new_password: str


def _user_out(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role,
            "must_change_password": u.must_change_password}


@router.post("/login")
def login(body: LoginIn, request: Request, session: Session = Depends(get_session)):
    ip = _client_ip(request)
    _rate_check(ip)                          # 429 if this source has failed too many times recently
    user = session.exec(select(User).where(User.username == body.username)).first()
    if not user or not verify_password(body.password, user.password_hash):
        _rate_note_fail(ip)
        raise HTTPException(401, "bad credentials")
    if user.role == "service":
        raise HTTPException(403, "service accounts authenticate with an API key, not a password")
    if user.totp_enabled:                    # password ok; require the 2FA code as a second step
        if not body.code:
            raise HTTPException(401, "2fa_required")      # not a failed attempt — the client now asks for a code
        if not verify_totp(user.totp_secret, body.code):
            _rate_note_fail(ip)
            raise HTTPException(401, "invalid 2fa code")
    _rate_clear(ip)                          # a good login resets the counter for this source
    return {"token": make_jwt(user), "user": _user_out(user)}


# ---- optional per-user two-factor auth (TOTP) --------------------------------------------------------------
@router.get("/2fa")
def twofa_status(user: User = Depends(current_user)):
    return {"enabled": user.totp_enabled}


@router.post("/2fa/setup")
def twofa_setup(user: User = Depends(current_user), session: Session = Depends(get_session)):
    """Generate a fresh secret (not enabled until confirmed with a code). Returns the secret + otpauth URI so
    the UI can render a QR. The secret is only shown here, during setup."""
    secret = new_totp_secret()
    user.totp_secret = secret
    user.totp_enabled = False
    session.add(user)
    session.commit()
    return {"secret": secret, "otpauth_uri": totp_uri(user.username, secret)}


@router.post("/2fa/enable")
def twofa_enable(body: CodeIn, user: User = Depends(current_user), session: Session = Depends(get_session)):
    if not user.totp_secret:
        raise HTTPException(400, "start setup first")
    if not verify_totp(user.totp_secret, body.code):
        raise HTTPException(400, "invalid code")
    user.totp_enabled = True
    session.add(user)
    session.commit()
    return {"enabled": True}


@router.post("/2fa/disable")
def twofa_disable(body: CodeIn, user: User = Depends(current_user), session: Session = Depends(get_session)):
    if user.totp_enabled and not verify_totp(user.totp_secret, body.code):
        raise HTTPException(400, "invalid code")
    user.totp_enabled = False
    user.totp_secret = None
    session.add(user)
    session.commit()
    return {"enabled": False}


@router.get("/me")
def me(user: User = Depends(current_user)):
    return _user_out(user)


@router.post("/change-password")
def change_password(body: ChangePw, user: User = Depends(current_user),
                    session: Session = Depends(get_session)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "current password is wrong")
    if len(body.new_password) < 4:
        raise HTTPException(400, "password too short")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    session.add(user)
    session.commit()
    return {"ok": True}

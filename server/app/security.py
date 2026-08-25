"""Password hashing, JWT for users, TOTP 2FA, and token auth for runners."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import jwt
from fastapi import Depends, Header, HTTPException
from passlib.context import CryptContext
from sqlmodel import Session, select

from .config import settings
from .db import get_session
from .models import ApiKey, Runner, User

API_KEY_PREFIX = "bck_"

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(p: str) -> str:
    return _pwd.hash(p)


def verify_password(p: str, h: str) -> bool:
    return _pwd.verify(p, h)


# ---- TOTP 2FA (RFC 6238, SHA-1, 6 digits, 30s) — stdlib only, no extra dependency -------------------------
def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp_code(secret_b32: str, when: float, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    h = hmac.new(key, struct.pack(">Q", int(when // step)), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    num = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(num).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    """Accept the code for the current 30s step ±`window` steps (clock-skew tolerance)."""
    if not (secret_b32 and code):
        return False
    code = str(code).strip()
    if not code.isdigit():
        return False
    now = time.time()
    return any(_totp_code(secret_b32, now + w * 30) == code for w in range(-window, window + 1))


def totp_uri(username: str, secret_b32: str, issuer: str = "boxcutter") -> str:
    return (f"otpauth://totp/{quote(issuer + ':' + username)}"
            f"?secret={secret_b32}&issuer={quote(issuer)}")


def hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def make_jwt(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    return jwt.encode({"sub": str(user.id), "u": user.username, "role": user.role, "exp": exp},
                      settings.secret_key, algorithm="HS256")


def decode_user(token: str, session: Session) -> User | None:
    """Validate a user JWT and return the User, or None. Shared by the header auth and the SSE query-param
    auth (EventSource can't send an Authorization header)."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return session.get(User, int(payload["sub"]))


def make_api_key() -> tuple[str, str, str]:
    """Return (full_key, prefix, key_hash). The full key is shown to the user once; only the hash is stored."""
    full = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return full, full[:12], hash_token(full)


def user_from_api_key(key: str, session: Session) -> User | None:
    row = session.exec(select(ApiKey).where(
        ApiKey.key_hash == hash_token(key), ApiKey.revoked == False)).first()  # noqa: E712
    if not row:
        return None
    row.last_used_at = datetime.now(timezone.utc)
    session.add(row)
    session.commit()
    return session.get(User, row.user_id)


def current_user(authorization: str = Header(default=""), x_api_key: str = Header(default=""),
                 session: Session = Depends(get_session)) -> User:
    """Accept either a user JWT (Bearer) or an API key (X-API-Key, or Bearer bck_...). API keys let users and
    system/service accounts drive the full REST API without a UI login."""
    bearer = authorization.split(" ", 1)[1] if authorization.lower().startswith("bearer ") else ""
    key = x_api_key or (bearer if bearer.startswith(API_KEY_PREFIX) else "")
    if key:
        user = user_from_api_key(key, session)
        if not user:
            raise HTTPException(401, "invalid api key")
        return user
    if not bearer:
        raise HTTPException(401, "missing bearer token")
    user = decode_user(bearer, session)
    if not user:
        raise HTTPException(401, "invalid token")
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "admin only")
    return user


def current_runner(authorization: str = Header(default=""), session: Session = Depends(get_session)) -> Runner:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing runner token")
    runner = session.exec(select(Runner).where(Runner.token_hash == hash_token(authorization.split(" ", 1)[1]))).first()
    if not runner:
        raise HTTPException(401, "unknown runner")
    return runner

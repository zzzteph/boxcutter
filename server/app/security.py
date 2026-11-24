"""Authentication.

* The UI (the SPA and every /api route) is behind HTTP basic auth with ONE account: `admin` / a password that
  starts as `admin` and is changed from Settings. There are no other users, roles, sessions or API keys.
* Scanner agents authenticate to /runner/* with the per-runner token they got at enrollment (an enroll token
  is the only way to enroll).

The basic-auth check runs as a tiny ASGI middleware so the static SPA and every API route are covered in one
place. Verified credentials are cached in memory (keyed by a hash of the header) so a polling UI doesn't pay a
PBKDF2 per request; the cache is dropped whenever the password changes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import threading
import time
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException
from sqlmodel import Session, select

from .config import settings
from .db import engine, get_session
from .models import AppSettings, Runner

_ITERATIONS = 200_000
_REALM = 'Basic realm="boxcutter", charset="UTF-8"'
# paths that are NOT behind basic auth: liveness, and the agent protocol (its own token auth)
_OPEN_PREFIXES = ("/health", "/runner/")


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _ITERATIONS).hex()
    return f"pbkdf2_sha256${_ITERATIONS}${salt}${dk}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, dk = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iters)).hex()
        return hmac.compare_digest(calc, dk)
    except Exception:  # noqa: BLE001
        return False


def hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


# ---- the admin password (cached hash + verified-credential cache) -----------------------------------------
_lock = threading.Lock()
_state = {"hash": None}
_ok_cache: set[str] = set()
_fails: dict[str, list[float]] = {}
_FAIL_WINDOW, _FAIL_MAX = 300.0, 10


def ensure_admin(session: Session) -> None:
    """First boot: store the hash of ADMIN_PASSWORD (default 'admin')."""
    row = session.get(AppSettings, 1)
    if row is None:
        row = AppSettings(id=1, admin_password_hash=hash_password(settings.admin_password))
        session.add(row)
        session.commit()
    elif not row.admin_password_hash:
        row.admin_password_hash = hash_password(settings.admin_password)
        session.add(row)
        session.commit()
    with _lock:
        _state["hash"] = row.admin_password_hash
        _ok_cache.clear()


def _current_hash() -> str:
    with _lock:
        h = _state["hash"]
    if h is None:
        with Session(engine) as s:
            ensure_admin(s)
        with _lock:
            h = _state["hash"]
    return h or ""


def set_admin_password(session: Session, new_password: str) -> None:
    row = session.get(AppSettings, 1) or AppSettings(id=1)
    row.admin_password_hash = hash_password(new_password)
    row.password_changed_at = datetime.now(timezone.utc)
    session.add(row)
    session.commit()
    with _lock:
        _state["hash"] = row.admin_password_hash
        _ok_cache.clear()


def check_credentials(username: str, password: str) -> bool:
    return hmac.compare_digest(username, settings.admin_user) and verify_password(password, _current_hash())


def _parse_basic(header: str) -> tuple[str, str] | None:
    if not header.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(header.split(" ", 1)[1].strip()).decode("utf-8")
    except Exception:  # noqa: BLE001
        return None
    user, sep, pw = raw.partition(":")
    return (user, pw) if sep else None


def _too_many_fails(ip: str) -> bool:
    now = time.time()
    fails = [t for t in _fails.get(ip, []) if now - t < _FAIL_WINDOW]
    if fails:
        _fails[ip] = fails
    else:
        _fails.pop(ip, None)
    return len(fails) >= _FAIL_MAX


def authorized(header: str, ip: str) -> tuple[bool, int]:
    """(ok, status) for an Authorization header. status is 401 (ask again) or 429 (rate-limited)."""
    key = hashlib.sha256(header.encode()).hexdigest() if header else ""
    if key:
        with _lock:
            if key in _ok_cache:
                return True, 200
    if _too_many_fails(ip):
        return False, 429
    creds = _parse_basic(header)
    if creds and check_credentials(*creds):
        with _lock:
            if len(_ok_cache) > 64:
                _ok_cache.clear()
            _ok_cache.add(key)
        _fails.pop(ip, None)
        return True, 200
    if creds:                                   # a wrong password counts; a bare page load (no header) doesn't
        _fails.setdefault(ip, []).append(time.time())
    return False, 401


class BasicAuthMiddleware:
    """Pure-ASGI basic auth for everything except /health and /runner/* (streaming-safe: no body buffering)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        if path.startswith(_OPEN_PREFIXES):
            return await self.app(scope, receive, send)
        header = ""
        for k, v in scope.get("headers", []):
            if k == b"authorization":
                header = v.decode("latin-1")
                break
        ip = (scope.get("client") or ("", 0))[0] or "unknown"
        ok, status = authorized(header, ip)
        if ok:
            return await self.app(scope, receive, send)
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = b"authentication required" if status == 401 else b"too many failed logins - try again later"
        headers = [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode())]
        if status == 401:
            headers.append((b"www-authenticate", _REALM.encode()))
        else:
            headers.append((b"retry-after", b"300"))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


# ---- runner (agent) auth ------------------------------------------------------------------------------------
def current_runner(authorization: str = Header(default=""), session: Session = Depends(get_session)) -> Runner:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing runner token")
    token = authorization.split(" ", 1)[1].strip()
    runner = session.exec(select(Runner).where(Runner.token_hash == hash_token(token))).first()
    if not runner:
        raise HTTPException(401, "unknown runner")
    return runner

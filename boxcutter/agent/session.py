"""Self-managed auth - bob logs in, stores access+refresh, and re-auths on expiry like a person.

This is deterministic CODE (not an LLM prompt) so authentication is reliable: it POSTs credentials,
extracts the token from JSON or Set-Cookie, and on a 401 it refreshes (or re-logs-in) and retries.
Driven through boxcutter's `http-request` tool via the same Runner the agents use.
"""

from __future__ import annotations

import json
import re

_USER_FIELDS = ("username", "user", "email", "login", "identifier", "userName")
_PASS_FIELDS = ("password", "pass", "passwd", "pwd")
_ACCESS_KEYS = ("access_token", "accessToken", "token", "jwt", "id_token", "idToken", "access", "authToken")
_REFRESH_KEYS = ("refresh_token", "refreshToken", "refresh")
_OK = (200, 201, 204)


def _item(out):
    try:
        env = json.loads(out)
    except Exception:  # noqa: BLE001
        return {}
    data = env.get("data") or []
    return data[0] if data and isinstance(data[0], dict) else {}


def _find(d, keys):
    if not isinstance(d, dict):
        return ""
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    for v in d.values():               # one level of nesting (e.g. {"data": {"token": ...}})
        if isinstance(v, dict):
            found = _find(v, keys)
            if found:
                return found
    return ""


def _parse_tokens(item):
    """Return (access, refresh, kind) from an http-request envelope item."""
    try:
        body = json.loads(item.get("content") or "")
    except Exception:  # noqa: BLE001
        body = {}
    access = _find(body, _ACCESS_KEYS) if isinstance(body, dict) else ""
    refresh = _find(body, _REFRESH_KEYS) if isinstance(body, dict) else ""
    kind = "bearer"
    if not access:                      # fall back to a session cookie
        headers = item.get("headers") or {}
        setc = next((v for k, v in headers.items() if k.lower() == "set-cookie"), "")
        m = re.search(r"([A-Za-z0-9_\-]+=[^;,\s]+)", setc)
        if m:
            access, kind = m.group(1), "cookie"
    return access, refresh, kind


def login(sess, runner) -> bool:
    """POST the credentials to the login URL; store access/refresh. True on success."""
    if not (sess.login_url and sess.creds):
        return False
    user, pw = sess.creds
    attempts = [
        (json.dumps({_USER_FIELDS[0]: user, _PASS_FIELDS[0]: pw}), "application/json"),
        (json.dumps({"email": user, "password": pw}), "application/json"),
        (f"username={user}&password={pw}", "application/x-www-form-urlencoded"),
    ]
    for body, ctype in attempts:
        item = _item(runner(["http-request", sess.login_url, "-D", body, "-H", f"Content-Type: {ctype}"],
                            allowed={"http-request"}))
        if int(item.get("status") or 0) in _OK:
            access, refresh, kind = _parse_tokens(item)
            if access:
                sess.access, sess.refresh, sess.kind, sess.alive = access, refresh, kind, True
                return True
    # fallback: a real browser login (SPA / CSRF token / redirect) when Playwright is available
    item = _item(runner(["browser-login", sess.login_url, "--creds", f"{user}:{pw}"], allowed={"browser-login"}))
    token, cookie = item.get("token"), item.get("cookie")
    if token:
        sess.access, sess.kind, sess.alive = token, "bearer", True
        return True
    if cookie:
        sess.access, sess.kind, sess.alive = cookie, "cookie", True
        return True
    return False


def refresh(sess, runner) -> bool:
    """Use the refresh token to mint a new access token; fall back to a full re-login."""
    if sess.refresh and sess.refresh_url:
        body = json.dumps({"refresh_token": sess.refresh, "grant_type": "refresh_token"})
        item = _item(runner(["http-request", sess.refresh_url, "-D", body, "-H", "Content-Type: application/json"],
                            allowed={"http-request"}))
        if int(item.get("status") or 0) in _OK:
            access, _, kind = _parse_tokens(item)
            if access:
                sess.access, sess.kind, sess.alive = access, kind or sess.kind, True
                return True
    return login(sess, runner)          # refresh failed or unavailable -> log in again


def is_unauthorized(out) -> bool:
    """True when an http-request envelope shows the session is logged out."""
    return int(_item(out).get("status") or 0) in (401, 403)

"""forge identity / session layer.

A hunt runs anonymous by default. When credentials are given, forge logs in through
a real browser (the browser-login tool: SPA / CSRF / redirect aware) and captures the
resulting session, an identity. An identity is a Cookie and/or a bearer token; its
headers are threaded into every header-capable tool call, so the whole pipeline runs
AS that user once login succeeds. A second identity (B) enables the differential
BOLA/BFLA test (bola-walk -A/-B). Modeled on vera's session/identity design.

Secrets are never printed in full: `masked()` shows only whether a value is set.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Identity:
    label: str
    cookie: str = ""
    token: str = ""
    alive: bool = False           # proven usable (a login returned a cookie/token)

    def headers(self) -> list[str]:
        """The request headers that carry this session, for --header propagation."""
        out: list[str] = []
        if self.cookie:
            out.append(f"Cookie: {self.cookie}")
        if self.token:
            out.append(f"Authorization: Bearer {self.token}")
        return out

    def masked(self) -> str:
        def m(v: str) -> str:
            if not v:
                return "none"
            return f"{v[:4]}...{v[-4:]}" if len(v) > 8 else "set"
        return f"identity {self.label}: cookie={m(self.cookie)} token={m(self.token)} alive={self.alive}"


def from_login_item(label: str, item: dict) -> Identity:
    """Build an identity from a browser-login result item {url, cookie, token, status}.
    Alive iff the login yielded a cookie or a token."""
    cookie = str((item or {}).get("cookie") or "")
    token = str((item or {}).get("token") or "")
    return Identity(label=label, cookie=cookie, token=token, alive=bool(cookie or token))

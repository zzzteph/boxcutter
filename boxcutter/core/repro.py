"""Copy-pasteable reproductions for a finding: a `curl` command and a raw HTTP/1.1 request you can paste into
Burp Repeater. One source of truth so every boxcutter tool hands the operator the same replayable request.

Usage in a tool that has the request it confirmed a finding with:

    from ..core import repro
    finding = {..., **repro.repro("POST", url, headers, body)}   # adds "curl" and "request"
"""
from __future__ import annotations

import shlex
from urllib.parse import urlparse


def curl(method: str, url: str, headers: dict | None = None, body: str | None = None) -> str:
    """A bash-quoted curl one-liner (-sk = silent, ignore TLS) that replays the request."""
    method = (method or "GET").upper()
    parts = [f"curl -sk -X {method} {shlex.quote(url)}"]
    for k, v in (headers or {}).items():
        parts.append(f"-H {shlex.quote(f'{k}: {v}')}")
    if body:
        parts.append(f"--data {shlex.quote(body)}")
    return " ".join(parts)


def raw_request(method: str, url: str, headers: dict | None = None, body: str | None = None) -> str:
    """A raw HTTP/1.1 request (CRLF line endings) ready to paste into Burp Repeater."""
    method = (method or "GET").upper()
    p = urlparse(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    hdrs = {"Host": p.netloc, **(headers or {})}
    if body:
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        hdrs["Content-Length"] = str(len(body))
    head = "\r\n".join(f"{k}: {v}" for k, v in hdrs.items())
    out = f"{method} {path} HTTP/1.1\r\n{head}\r\n\r\n"
    return out + body if body else out


def repro(method: str, url: str, headers: dict | None = None, body: str | None = None) -> dict:
    """`{"curl": ..., "request": ...}` to merge straight into a finding dict."""
    return {"curl": curl(method, url, headers, body), "request": raw_request(method, url, headers, body)}

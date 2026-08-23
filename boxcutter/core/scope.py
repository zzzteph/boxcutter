"""Scope: keep a workflow's collected URLs/hosts/findings within the target's domain.

A workflow's scope is, by default, the registrable domain (eTLD+1) of its initial target, so scanning
``skipthedishes.com`` keeps ``api.skipthedishes.com`` / ``android-es.staging.skipthedishes.com`` but drops
third-party hosts a crawl pulls in (``googletagmanager.com``, ``fonts.googleapis.com``, a CDN). This stops
the scanners from ever touching, and reporting bogus findings on, assets that are not the target.

Best-effort and dependency-free: eTLD+1 is derived with a small known multi-label-suffix set (co.uk, com.au,
...), not a full Public Suffix List. Callers can override the scope explicitly (see the workflow --scope flag).
"""

from __future__ import annotations

import string
from urllib.parse import urlparse

# Registrable domain needs three labels under these public suffixes (example.co.uk -> example.co.uk, not co.uk).
# Not exhaustive - the common country-code second-level domains.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "id.au",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.za", "org.za", "net.za",
    "com.br", "net.br", "gov.br", "org.br",
    "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp",
    "co.in", "net.in", "org.in", "gov.in", "firm.in",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "com.ar", "com.sg", "com.tr", "com.ua", "com.pl", "com.hk", "com.tw",
    "co.kr", "or.kr", "co.il", "co.id",
}

_HOST_CHARS = set(string.ascii_lowercase + string.digits + ".-_")


def host_of(value: str) -> str:
    """Hostname of a URL or bare host, lowercased and without scheme/port/path. Returns "" for a string that
    does not look like a host (no dot, or invalid characters) so non-host data is never treated as in/out of scope."""
    v = (value or "").strip()
    if not v or any(ws in v for ws in " \t\r\n"):
        return ""
    host = (urlparse(v if "://" in v else "//" + v).hostname or "").lower().rstrip(".")
    if not host or "." not in host or any(ch not in _HOST_CHARS for ch in host):
        return ""
    return host


def _is_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def registrable_domain(host: str) -> str:
    """eTLD+1 of a host, best-effort. ``api.example.com`` -> ``example.com``; ``a.b.example.co.uk`` ->
    ``example.co.uk``; an IP is returned unchanged."""
    host = host_of(host)
    if not host or _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_SUFFIX and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def scope_bases(target: str) -> list[str]:
    """Default in-scope base(s) for a workflow's initial target: its registrable domain (empty if none)."""
    base = registrable_domain(target)
    return [base] if base else []


def in_scope(value: str, bases: list[str]) -> bool:
    """Is ``value`` (a URL or host) within any base - equal to it, or a subdomain of it? A value that is not a
    URL/host, and an empty ``bases``, are both treated as in scope (True) so nothing unrelated is dropped."""
    if not bases:
        return True
    host = host_of(value)
    if not host:
        return True
    return any(host == base or host.endswith("." + base) for base in bases)

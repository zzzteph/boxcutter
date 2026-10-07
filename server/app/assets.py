"""Classify a discovered scan item by asset TYPE (domain / subdomain / url / ip / endpoint / other).

Ported from the engine's dependency-free registrable-domain logic (boxcutter/core/scope.py) so the server stays
standalone AND the domain/subdomain split matches the scanner's own notion of scope. Best-effort eTLD+1 via a
small common multi-label-suffix set (co.uk, com.au, ...), not the full Public Suffix List — good enough for the
common cases; a rare suffix just classifies one label too shallow.
"""
from __future__ import annotations

import string
from urllib.parse import urlparse

# registrable domain needs three labels under these suffixes (example.co.uk -> example.co.uk, not co.uk)
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

ASSET_TYPES = ("domain", "subdomain", "url", "ip", "endpoint", "other")


def _host_of(value: str) -> str:
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


def _registrable_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_SUFFIX and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def classify(value: str) -> str:
    """The asset type of a listable scan-item value.

    url       -> has a scheme (http:// or https://)
    ip        -> a bare IPv4 (optionally with a port)
    endpoint  -> host:port (a non-HTTP service, e.g. from a port scan)
    domain    -> a registrable domain / eTLD+1 (example.com, example.co.uk)
    subdomain -> a host with labels below its registrable domain (api.example.com)
    other     -> anything that isn't a host (a path, an id, a free string)
    """
    v = (value or "").strip()
    if not v:
        return "other"
    low = v.lower()
    if low.startswith(("http://", "https://")):
        return "url"
    host = _host_of(v)
    if not host:
        return "other"
    if _is_ip(host):
        return "ip"
    # host:port with no scheme and a numeric port that isn't a web port -> treat as a service endpoint
    tail = v.rsplit(":", 1)
    if len(tail) == 2 and tail[1].isdigit() and "/" not in v and tail[1] not in ("80", "443"):
        return "endpoint"
    return "domain" if host == _registrable_domain(host) else "subdomain"

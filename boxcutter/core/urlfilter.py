"""URL classification helpers shared by the crawlers and wayback.

Ports the ``isValidHttpUrl`` / ``isValidJsUrl`` / ``isValidUrlWithParams``
helpers that appear identically in KatanaCrawl, ZapCrawl and (in spirit)
Wayback.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

# Extensions that are never interesting as "parameterised" URLs.
_PARAM_SKIP_EXT = {"js", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css"}


def path_extension(path: str) -> str:
    """Lowercased file extension of a URL path (no leading dot)."""
    tail = path.rsplit("/", 1)[-1]
    if "." not in tail:
        return ""
    return tail.rsplit(".", 1)[-1].lower()


def is_http_url(value: str) -> bool:
    parts = urlparse(value)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def is_js_url(value: str) -> bool:
    parts = urlparse(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return False
    return path_extension(parts.path) == "js"


def is_url_with_params(value: str) -> bool:
    parts = urlparse(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return False
    if not parts.query:
        return False
    return path_extension(parts.path) not in _PARAM_SKIP_EXT


def keep_url(url: str, js_only: bool, params_only: bool) -> bool:
    """Apply the same keep/drop logic the crawlers use per discovered URL."""
    if not url:
        return False
    if js_only:
        return is_js_url(url)
    if params_only:
        return is_url_with_params(url)
    return is_http_url(url)


def param_signature(url: str) -> str | None:
    """scheme+host+path plus sorted *param names* (no values).

    ``/x?a=1&b=2`` and ``/x?a=9&b=8`` collapse to one signature; ``/x?a=1`` and
    ``/x?a=1&b=2`` stay distinct. Port of Wayback::paramSignature.
    """
    parts = urlparse(url)
    if not parts.query:
        return None
    params = parse_qs(parts.query, keep_blank_values=True)
    if not params:
        return None
    names = sorted(params.keys())
    host = (parts.hostname or "").lower()
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}{parts.path}?" + ",".join(names)


def dedupe_param_urls(urls: list[str]) -> list[str]:
    """Keep one URL per (path + sorted param-name set), ignoring param values.

    Collapses ``/x?id=1&cHash=a`` and ``/x?cHash=b&id=2`` to a single URL so a
    workflow scans each distinct endpoint once instead of once per value.
    """
    seen: dict[str, str] = {}
    for url in urls:
        key = param_signature(url) or url
        if key not in seen:
            seen[key] = url
    return list(seen.values())

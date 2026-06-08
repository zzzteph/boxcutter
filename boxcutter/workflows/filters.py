"""List filters usable in YAML workflows via ``${name | filter | filter}``.

Each filter takes a list and returns a list. They are thin wrappers over the
existing url helpers, so a YAML workflow can shape a URL set without any Python.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..core.envelope import dedupe
from ..core.urlfilter import dedupe_param_urls, is_js_url, is_url_with_params


def _params(items: list) -> list:
    return [u for u in items if isinstance(u, str) and is_url_with_params(u)]


def _js(items: list) -> list:
    return [u for u in items if isinstance(u, str) and is_js_url(u)]


def _dedup(items: list) -> list:
    """Collapse param URLs by path + param-name set (ignores values)."""
    return dedupe_param_urls([u for u in items if isinstance(u, str)])


def _unique(items: list) -> list:
    """Order-preserving de-duplication of a string list."""
    return dedupe([u for u in items if isinstance(u, str)])


def _hosts(items: list) -> list:
    """Hostname of each value; a bare domain (no scheme) is kept as-is."""
    out: list[str] = []
    for u in items:
        if not isinstance(u, str):
            continue
        out.append(urlparse(u).hostname or u)
    return dedupe(out)


def _url(items: list) -> list:
    """Ensure each value has a scheme (prepend https:// to bare hosts)."""
    out: list[str] = []
    for u in items:
        if not isinstance(u, str) or not u:
            continue
        out.append(u if u.startswith(("http://", "https://")) else "https://" + u)
    return out


FILTERS = {
    "params": _params,
    "js": _js,
    "dedup": _dedup,
    "unique": _unique,
    "hosts": _hosts,
    "url": _url,
}

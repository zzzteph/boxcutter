"""List filters usable in YAML workflows via ``${name | filter | filter}``.

Two kinds of filter:

* **Plain filters** take a list and return a list (``FILTERS``). They are thin
  wrappers over the url helpers, so a workflow can shape a URL set with no Python.
* **Parametric filters** take an argument and a list (``PARAM_FILTERS``), written
  ``name:arg`` in a ref, e.g. ``${findings | class:sql}``. They select findings by
  a property (vulnerability class) so a step's ``when:``/``unless:`` guard can key
  on what an earlier step found.
"""

from __future__ import annotations

import re
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


_WRITE_METHODS = {"POST", "PUT", "PATCH"}


def _urls(items: list) -> list:
    """Each item's URL: an object's ``url`` field, or a string passed through. Flattens harvest's corpus of
    objects into the URL string list the ``| js|params`` filters and the fuzzers expect."""
    out: list[str] = []
    for it in items:
        if isinstance(it, str):
            out.append(it)
        elif isinstance(it, dict) and it.get("url"):
            out.append(it["url"])
    return dedupe(out)


def _writes(items: list) -> list:
    """Keep the state-changing endpoints (POST/PUT/PATCH objects), the ones a URL-string pipeline drops. Their
    method/body/headers are then passed to a fuzzer via a step's ``flags:``."""
    return [it for it in items if isinstance(it, dict)
            and str(it.get("method", "")).upper() in _WRITE_METHODS]


FILTERS = {
    "params": _params,
    "js": _js,
    "dedup": _dedup,
    "unique": _unique,
    "hosts": _hosts,
    "url": _url,
    "urls": _urls,
    "writes": _writes,
}


# --- parametric filters: select findings by vulnerability class ---------------
#
# A finding's class is read from (in order) its explicit ``class`` field, the
# bracketed tags in its ``title`` (fuzz emits ``[GET] [sqli] in 'id' (...)``), and
# a ``Class: <c>`` line in its ``info``. Matching is exact per token (so ``sql``
# does NOT match ``nosql``), with a small alias table folding common synonyms -
# ``sql`` -> ``sqli`` - so a workflow can write the class the way a human says it.

_CLASS_ALIASES = {"sql": "sqli", "sqlinjection": "sqli", "injection": "sqli"}
_TAG_RE = re.compile(r"\[([A-Za-z0-9_.-]+)\]")
_INFO_CLASS_RE = re.compile(r"class:\s*([A-Za-z0-9_.-]+)", re.I)


def _class_tokens(f: dict) -> set:
    """Every class token a finding carries, lower-cased."""
    toks: set[str] = set()
    if not isinstance(f, dict):
        return toks
    cls = f.get("class")
    if isinstance(cls, str) and cls:
        toks.add(cls.lower())
    for tag in _TAG_RE.findall(str(f.get("title", ""))):
        toks.add(tag.lower())
    m = _INFO_CLASS_RE.search(str(f.get("info", "")))
    if m:
        toks.add(m.group(1).lower())
    return toks


def _class_matches(arg: str, f: dict) -> bool:
    want = arg.strip().lower()
    want = _CLASS_ALIASES.get(want, want)
    return want in _class_tokens(f)


def _class(arg: str, items: list) -> list:
    """Keep only findings of vulnerability class ``arg`` (e.g. ``class:sql``)."""
    return [f for f in items if _class_matches(arg, f)]


def _not_class(arg: str, items: list) -> list:
    """Drop findings of vulnerability class ``arg``; keep everything else."""
    return [f for f in items if not _class_matches(arg, f)]


PARAM_FILTERS = {
    "class": _class,
    "not-class": _not_class,
}

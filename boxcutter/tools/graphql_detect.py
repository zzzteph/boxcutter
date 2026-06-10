"""graphql-detect: probe a host for a GraphQL endpoint and list the URL(s) found.

POSTs a tiny ``{__typename}`` query to common GraphQL mount points and confirms by
*response shape* - a GraphQL engine either answers with ``data`` or rejects the
probe with GraphQL-style ``errors`` (status code alone is useless here). Emits the
endpoint URLs so a workflow can run ``graphql-audit`` on each.
"""
from __future__ import annotations

import json as jsonlib
import re
from urllib.parse import urlparse

from ..core import http
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result

NAME = "graphql-detect"
KIND = "urls"
HELP = "Probe common paths for a GraphQL endpoint and list the URL(s) found."

COMMON_PATHS = [
    "/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/api", "/gql", "/api/gql", "/graphql/console", "/graphiql", "/playground",
]

_PROBE = {"query": "{__typename}"}
# Phrases a GraphQL engine emits when it rejects a probe (confirms it's GraphQL).
_GQL_ERR = re.compile(
    r"must be defined|cannot query field|cannot parse|parse query|syntax error|"
    r"graphql|unknown operation|did you mean|querytype|operation .* not", re.I,
)


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target host or URL, e.g. https://api.foo.com")
    parser.add_argument("--timeout", type=int, default=8, help="Per-request timeout (s)")
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    dbg = debug_logger(args.debug)
    base = _normalize(args.target.strip())
    if base is None:
        output_result([], args.output, "Invalid target.")
        return 1
    headers = _header_map(args.header)
    headers.setdefault("Content-Type", "application/json")

    found: list[str] = []
    for path in COMMON_PATHS:
        url = base + path
        if url in found:
            continue
        if _is_graphql(url, headers, args.timeout, dbg):
            dbg(f"graphql endpoint: {url}")
            found.append(url)
    output_result(found, args.output)
    return 0


def _is_graphql(url, headers, timeout, dbg) -> bool:
    # 1) POST {__typename}
    if _looks_graphql(http.send("POST", url, json=_PROBE, headers=headers, timeout=timeout)):
        return True
    # 2) some endpoints only answer over GET
    if _looks_graphql(http.send("GET", url, params={"query": "{__typename}"}, headers=headers, timeout=timeout)):
        return True
    # 3) a GraphiQL / Playground UI also proves a GraphQL endpoint is mounted here
    r = http.send("GET", url, headers=headers, timeout=timeout)
    body = r.get("body") or ""
    if r.get("status") == 200 and re.search(r"graphiql|graphql ?playground", body, re.I):
        return True
    return False


def _looks_graphql(r) -> bool:
    if r.get("error") or r.get("status") is None:
        return False
    try:
        doc = jsonlib.loads(r.get("body") or "")
    except ValueError:
        return False
    if not isinstance(doc, dict):
        return False
    # GraphQL wraps results under "data"; our probe asks for a meta field, so a real
    # server answers data.__typename (some non-compliant ones echo __schema/__type).
    data = doc.get("data")
    if isinstance(data, dict) and any(k in data for k in ("__typename", "__schema", "__type")):
        return True
    # ... or it rejects the probe with GraphQL-style errors (still proves it's GraphQL)
    errs = doc.get("errors")
    return isinstance(errs, list) and bool(errs) and bool(_GQL_ERR.search(jsonlib.dumps(errs)))


def _normalize(value: str) -> str | None:
    if not value:
        return None
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parts = urlparse(value)
    if not parts.hostname:
        return None
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme or 'https'}://{parts.hostname}{port}"


def _header_map(headers: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in headers or []:
        if ":" in raw:
            name, value = raw.split(":", 1)
            if name.strip():
                out[name.strip()] = value.strip()
    return out

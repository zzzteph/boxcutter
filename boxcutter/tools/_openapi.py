"""Shared OpenAPI/Swagger spec loading (JSON first, YAML fallback)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlencode, urlparse

_VERBS = ("get", "post", "put", "patch", "delete")


def parse_spec(body: str) -> tuple[Any, str | None]:
    """Parse a spec body. Returns ``(spec, error)``.

    JSON is tried first (most common), then YAML via PyYAML if installed. A
    ``None`` spec with a ``None`` error means "parsed but empty/falsy".
    """
    try:
        spec = json.loads(body)
    except json.JSONDecodeError:
        spec = None

    if spec:
        return spec, None

    try:
        import yaml  # type: ignore
    except ImportError:
        # Not JSON, and no YAML parser available. Most often the URL just isn't
        # a spec (e.g. a 404 HTML page); install PyYAML to also accept YAML.
        return None, "Could not parse spec as JSON or YAML."

    try:
        spec = yaml.safe_load(body)
    except Exception as exc:  # noqa: BLE001
        return None, f"Could not parse spec as JSON or YAML: {exc}"

    return spec, None


def is_spec(spec: Any) -> bool:
    """True when the parsed object looks like a Swagger/OpenAPI document."""
    return (
        isinstance(spec, dict)
        and ("swagger" in spec or "openapi" in spec)
        and isinstance(spec.get("paths"), dict)
    )


def base_url(spec: dict, spec_url: str | None = None) -> str | None:
    """Resolve the spec's server base URL (OpenAPI 3 ``servers`` or Swagger 2 host).

    A relative server URL (e.g. ``/api/v3``) or a missing server is resolved
    against ``spec_url``'s origin so endpoint URLs come out absolute/scannable.
    """
    origin = ""
    if spec_url:
        parts = urlparse(spec_url)
        if parts.scheme and parts.netloc:
            origin = f"{parts.scheme}://{parts.netloc}"

    servers = spec.get("servers")
    if servers and (servers[0] or {}).get("url"):
        raw = str(servers[0]["url"]).rstrip("/")
        if raw.startswith(("http://", "https://")):
            return raw
        return (origin + raw).rstrip("/") if origin else raw

    if spec.get("host"):
        scheme = (spec.get("schemes") or ["https"])[0]
        return f"{scheme}://{spec['host']}{spec.get('basePath', '')}".rstrip("/")

    return origin or None


def operations(spec: dict) -> list[dict]:
    """Flatten paths into ``{path, parameters}`` operations (one per verb)."""
    ops: list[dict] = []
    for path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        shared = methods.get("parameters") if isinstance(methods.get("parameters"), list) else []
        for verb, op in methods.items():
            if verb.lower() not in _VERBS or not isinstance(op, dict):
                continue
            op_params = op.get("parameters") if isinstance(op.get("parameters"), list) else []
            ops.append({"path": str(path), "parameters": [*shared, *op_params]})
    return ops


def _param_names(op: dict, where: str) -> list[str]:
    return [
        p["name"] for p in op["parameters"]
        if isinstance(p, dict) and "$ref" not in p and p.get("in") == where
        and isinstance(p.get("name"), str) and p["name"]
    ]


def endpoint_urls(spec: dict, spec_url: str | None = None, fuzzable: bool = False) -> list[str]:
    """Build scannable endpoint URLs from a spec.

    Default: concrete URLs (path params -> 1, query params -> sample value).
    ``fuzzable=True``: one ``{FUZZ}``-marked variant per path/query param, for
    the fuzz tool. ``spec_url`` resolves relative server URLs to absolute.
    """
    base = base_url(spec, spec_url)
    if not base:
        return []

    urls: list[str] = []
    for op in operations(spec):
        path_params = _param_names(op, "path")
        query_params = _param_names(op, "query")

        if not fuzzable:
            path = op["path"]
            for pp in path_params:
                path = path.replace("{" + pp + "}", "1")
            query = {qp: "1" for qp in query_params}
            urls.append(base + path + ("?" + urlencode(query) if query else ""))
            continue

        for pp in path_params:  # one {FUZZ} per path param
            path = op["path"]
            for other in path_params:
                path = path.replace("{" + other + "}", "{FUZZ}" if other == pp else "1")
            urls.append(base + path)
        sample_path = op["path"]
        for pp in path_params:
            sample_path = sample_path.replace("{" + pp + "}", "1")
        for qp in query_params:  # one {FUZZ} per query param
            query = {o: ("{FUZZ}" if o == qp else "test") for o in query_params}
            # safe="{}" keeps the {FUZZ} marker literal (not %7BFUZZ%7D) so the fuzz
            # tool sees it as a marker and injects only this param, matching how the
            # path-param variants above emit a raw {FUZZ}.
            urls.append(base + sample_path + "?" + urlencode(query, safe="{}"))

    seen: list[str] = []
    for url in urls:
        if url not in seen:
            seen.append(url)
    return seen

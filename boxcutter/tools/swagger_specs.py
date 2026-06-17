"""swagger-specs: probe a host for OpenAPI/Swagger specs and list the ones found.

Emits the spec URLs that parse as a valid spec, so a workflow can run
swagger-endpoints on each.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import http
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result
from . import _openapi

NAME = "swagger-specs"
KIND = "urls"
HELP = "Probe common OpenAPI/Swagger paths on a host and list the spec URLs found."

COMMON_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/api-docs", "/api-docs.json", "/api/docs",
    "/api/swagger.json", "/api/openapi.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json", "/api/v3/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json", "/api/v3/openapi.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/swagger-ui/swagger.json", "/swagger-resources",
]


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target host or URL, e.g. https://api.foo.com")
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    dbg = debug_logger(args.debug)
    raw = args.target.strip()
    base = _normalize(raw)
    if base is None:
        output_result([], args.output, "Invalid target.")
        return 1

    headers = _header_map(args.header)
    # Test the host's common spec paths, but also the target URL itself first - so a
    # direct spec link (e.g. a spec at a non-standard path) is picked up too. This
    # lets the swagger workflows accept a bare host OR a spec URL with one input.
    raw_url = raw if re.match(r"^https?://", raw, re.I) else "https://" + raw
    candidates: list[str] = []
    if urlparse(raw_url).path.strip("/"):
        candidates.append(raw_url)
    candidates += [base + path for path in COMMON_PATHS]

    found: list[str] = []
    for url in candidates:
        try:
            response = http.get(url, timeout=8, headers=headers, verify=False)
        except Exception:  # noqa: BLE001
            continue
        if not http.is_successful(response):
            continue
        spec, _ = _openapi.parse_spec(response.text)
        if _openapi.is_spec(spec):
            dbg(f"spec found: {url}")
            found.append(url)

    # Dedupe order-preserving (the target URL may also be one of COMMON_PATHS).
    output_result(list(dict.fromkeys(found)), args.output)
    return 0


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

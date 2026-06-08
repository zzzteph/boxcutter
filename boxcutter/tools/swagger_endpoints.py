"""swagger-endpoints: turn an OpenAPI/Swagger spec into scannable endpoint URLs.

Default output is concrete URLs (path params filled, query params sampled);
``--fuzzable`` emits {FUZZ}-marked path/query variants for the fuzz tool. Used
on its own or as the first step of the swagger workflows.
"""

from __future__ import annotations

from ..core import http
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url
from . import _openapi

NAME = "swagger-endpoints"
KIND = "urls"
HELP = "List endpoint URLs from an OpenAPI/Swagger spec (--fuzzable for {FUZZ}-marked variants)."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL to an OpenAPI/Swagger spec (JSON or YAML)")
    parser.add_argument(
        "--fuzzable", action="store_true",
        help="Emit {FUZZ}-marked path/query variants instead of concrete URLs",
    )
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target = args.target.strip()
    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    headers = _header_map(args.header)
    try:
        response = http.get(target, timeout=30, headers=headers, verify=False)
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"Request failed: {exc}")
        return 1

    if not http.is_successful(response):
        dbg(f"non-2xx ({response.status_code}) from {target}")
        output_result([], args.output)
        return 0

    spec, _ = _openapi.parse_spec(response.text)
    if not _openapi.is_spec(spec):
        dbg("response is not a Swagger/OpenAPI spec")
        output_result([], args.output)
        return 0

    urls = _openapi.endpoint_urls(spec, spec_url=target, fuzzable=args.fuzzable)
    dbg(f"{len(urls)} endpoint URL(s)")
    output_result(urls, args.output)
    return 0


def _header_map(headers: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in headers or []:
        if ":" in raw:
            name, value = raw.split(":", 1)
            if name.strip():
                out[name.strip()] = value.strip()
    return out

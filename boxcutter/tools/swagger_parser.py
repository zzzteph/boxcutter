"""swagger-parser - fetch + structure an OpenAPI/Swagger spec. Port of app:swagger-parser."""

from __future__ import annotations

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import output_result
from . import _openapi

NAME = "swagger-parser"
KIND = "items"
HELP = "Fetch and parse an OpenAPI/Swagger spec into a structured endpoint list."

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head"}


def add_arguments(parser) -> None:
    parser.add_argument("spec_url", help="Full URL of the OpenAPI/Swagger spec (JSON or YAML)")
    parser.add_argument("--base-url", dest="base_url", default="", help="Base URL to prepend to all paths")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Extra header (repeatable)")
    add_common_args(parser)


def run(args) -> int:
    spec_url = args.spec_url.strip()
    base_url = (args.base_url or "").rstrip("/")
    headers = _parse_headers(args.header)

    try:
        response = http.get(spec_url, timeout=30, headers=headers, verify=True)
    except Exception as exc:
        output_result([], args.output, str(exc))
        return 1

    if not http.is_successful(response):
        output_result([], args.output, f"HTTP {response.status_code} fetching spec")
        return 1

    spec, error = _openapi.parse_spec(response.text)
    if error:
        output_result([], args.output, error)
        return 1

    if not isinstance(spec, dict) or not spec.get("paths"):
        keys = ", ".join((spec or {}).keys()) if isinstance(spec, dict) else ""
        output_result([], args.output, f"Spec has no paths object. Top-level keys: {keys}")
        return 1

    if not base_url and spec.get("servers"):
        base_url = str((spec["servers"][0] or {}).get("url", "")).rstrip("/")

    endpoints: list[dict] = []
    for path, path_item in spec["paths"].items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue

            params = []
            for param in operation.get("parameters", []) or []:
                if not isinstance(param, dict) or "name" not in param:
                    continue
                schema = param.get("schema") or {}
                params.append(
                    {
                        "name": param["name"],
                        "in": param.get("in", "query"),
                        "required": param.get("required", False),
                        "type": schema.get("type", param.get("type", "string")),
                        "example": param.get("example", schema.get("example")),
                    }
                )

            request_body = None
            if "requestBody" in operation:
                content_types = operation["requestBody"].get("content", {}) or {}
                json_content = content_types.get("application/json") or (
                    next(iter(content_types.values()), {}) if content_types else {}
                )
                body_schema = (json_content or {}).get("schema", {}) or {}
                properties = {
                    field: {"type": defn.get("type", "string"), "example": defn.get("example")}
                    for field, defn in (body_schema.get("properties", {}) or {}).items()
                }
                request_body = {
                    "required": operation["requestBody"].get("required", False),
                    "required_fields": body_schema.get("required", []),
                    "properties": properties,
                }

            endpoints.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "url": base_url + path,
                    "operation_id": operation.get("operationId"),
                    "summary": operation.get("summary"),
                    "tags": operation.get("tags", []),
                    "parameters": params,
                    "request_body": request_body,
                }
            )

    output_result(
        [
            {
                "url": spec_url,
                "api_title": (spec.get("info") or {}).get("title"),
                "api_version": (spec.get("info") or {}).get("version"),
                "servers": [s.get("url", "") for s in (spec.get("servers") or [])],
                "total": len(endpoints),
                "endpoints": endpoints,
            }
        ],
        args.output,
    )
    return 0


def _parse_headers(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in raw_headers or []:
        if ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        if name.strip():
            headers[name.strip()] = value.strip()
    return headers

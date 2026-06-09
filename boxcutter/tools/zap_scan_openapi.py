"""zap-scan-openapi - ZAP active scan driven by an OpenAPI/Swagger spec URL.
Port of app:zap-scan-openapi.

Fetches the spec, derives the base/target URL (servers[0].url for OpenAPI 3.x,
host/basePath for Swagger 2.x; regex fallback for YAML), then runs an active
scan over the spec's endpoints.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse

from ..core import http
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url
from . import _zap

NAME = "zap-scan-openapi"
KIND = "findings"
HELP = "ZAP active scan driven by an OpenAPI/Swagger specification URL."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL of the OpenAPI/Swagger spec (JSON or YAML)")
    parser.add_argument("--timeout", type=int, default=900, help="Process timeout in seconds")
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    spec_url = args.target.strip()
    dbg = debug_logger(args.debug)

    if not is_valid_url(spec_url):
        output_result([], args.output, "Invalid spec URL.")
        return 1

    headers = _zap.header_map(args.header)
    dbg(f"Fetching spec: {spec_url}")
    try:
        response = http.get(spec_url, timeout=30, headers=headers or None, verify=False)
        spec_content = response.text
    except Exception:
        output_result([], args.output, f"Could not fetch spec from: {spec_url}")
        return 1

    if not _looks_like_spec(spec_content):
        dbg(f"Not a valid OpenAPI/Swagger spec at {spec_url}")
        output_result([], args.output)
        return 0

    target_url = _parse_target_from_spec(spec_content, spec_url)
    dbg(f"Parsed target: {target_url}")

    run_ = _zap.prepare_run()
    plan = _build_plan(spec_url, target_url, run_.report_path)
    cfg = _zap.replacer_configs(headers)
    _zap.execute(run_, plan, args.timeout, dbg, extra_config=cfg)

    if not os.path.exists(run_.report_path):
        _zap.cleanup(run_)
        output_result([], args.output, "ZAP report was not generated.")
        return 1

    alerts = _zap.read_alerts(run_.report_path)
    dbg(f"Found {len(alerts)} matching alerts.")
    findings = _zap.alerts_to_findings(alerts)
    _zap.cleanup(run_)

    output_result(findings, args.output)
    return 0


def _looks_like_spec(content: str) -> bool:
    try:
        decoded = json.loads(content)
    except json.JSONDecodeError:
        decoded = None
    if isinstance(decoded, dict):
        return (
            ("swagger" in decoded or "openapi" in decoded)
            and isinstance(decoded.get("paths"), dict)
        )
    has_version = re.search(r"^(swagger|openapi)\s*:", content, re.M) is not None
    has_paths = re.search(r"^paths\s*:", content, re.M) is not None
    return has_version and has_paths


def _parse_target_from_spec(content: str, spec_url: str) -> str:
    try:
        doc = json.loads(content)
    except json.JSONDecodeError:
        doc = None

    if isinstance(doc, dict):
        servers = doc.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict) and servers[0].get("url"):
            url = servers[0]["url"]
            if url.startswith("/"):
                url = _resolve_relative(url, spec_url)
            return url.rstrip("/") + "/"
        if doc.get("host"):
            schemes = doc.get("schemes") or []
            scheme = schemes[0] if schemes else "https"
            base_path = (doc.get("basePath") or "").rstrip("/")
            return f"{scheme}://{doc['host']}{base_path}/"

    yaml_fields = _parse_yaml_fields(content)
    if "servers_url" in yaml_fields:
        url = yaml_fields["servers_url"]
        if url.startswith("/"):
            url = _resolve_relative(url, spec_url)
        return url.rstrip("/") + "/"
    if "host" in yaml_fields:
        scheme = yaml_fields.get("schemes", "https")
        base_path = yaml_fields.get("basePath", "").rstrip("/")
        return f"{scheme}://{yaml_fields['host']}{base_path}/"

    parts = urlparse(spec_url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme or 'https'}://{parts.hostname or ''}{port}/"


def _resolve_relative(path: str, spec_url: str) -> str:
    parts = urlparse(spec_url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme or 'https'}://{parts.hostname or ''}{port}{path}"


def _parse_yaml_fields(content: str) -> dict:
    result: dict[str, str] = {}
    if re.search(r"^servers\s*:", content, re.M):
        m = re.search(r"^servers\s*:.*?^\s+-\s+url\s*:\s*[\"']?([^\s\"'#\n]+)", content, re.M | re.S)
        if m:
            result["servers_url"] = m.group(1).strip("'\"")
    if m := re.search(r"^host\s*:\s*[\"']?([^\s\"'#\n]+)", content, re.M):
        result["host"] = m.group(1).strip("'\"")
    if m := re.search(r"^basePath\s*:\s*[\"']?([^\s\"'#\n]+)", content, re.M):
        result["basePath"] = m.group(1).strip("'\"")
    if m := re.search(r"^schemes\s*:[\s\S]*?^\s+-\s*[\"']?(\w+)", content, re.M):
        result["schemes"] = m.group(1).strip("'\"")
    return result


def _build_plan(spec_url: str, target_url: str, report_path: str) -> str:
    context_url = _zap.yaml_quote(target_url)
    api_url = _zap.yaml_quote(spec_url)
    target = _zap.yaml_quote(target_url)
    report_file = _zap.yaml_quote(os.path.basename(report_path))
    report_dir = _zap.yaml_quote(os.path.dirname(report_path))
    return f"""env:
  contexts:
    - name: target
      urls:
        - {context_url}

jobs:
  - type: openapi
    parameters:
      apiUrl:    {api_url}
      targetUrl: {target}
      context: target

  - type: activeScan
    parameters:
      context: target
      addQueryParam: false
      handleAntiCSRFTokens: true
      scanHeadersAllRequests: false
      delayInMs: 100
      threadPerHost: 2
      maxRuleDurationInMins: 4
      maxScanDurationInMins: 12
    policyDefinition:
      defaultStrength: medium
      defaultThreshold: low

  - type: report
    parameters:
      template: traditional-json
      reportDir: {report_dir}
      reportFile: {report_file}
      reportTitle: 'ZAP OpenAPI Scan'
    risks:
      - high
      - medium
    confidences:
      - high
      - medium
"""

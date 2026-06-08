"""zap-scan-url - ZAP active scan against a single exact URL (no crawling).
Port of app:zap-scan-url."""

from __future__ import annotations

import os

from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url
from . import _zap

NAME = "zap-scan-url"
KIND = "findings"
HELP = "ZAP active scan against a single exact URL (no crawling)."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--timeout", type=int, default=900, help="Process timeout in seconds")
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    run = _zap.prepare_run()
    plan = _build_plan(target, run.report_path)
    dbg(f"Target: {target}")
    _zap.execute(run, plan, args.timeout, dbg)

    if not os.path.exists(run.report_path):
        _zap.cleanup(run)
        output_result([], args.output, "ZAP report was not generated.")
        return 1

    alerts = _zap.read_alerts(run.report_path)
    dbg(f"Found {len(alerts)} matching alerts.")
    findings = _zap.alerts_to_findings(alerts)
    _zap.cleanup(run)

    output_result(findings, args.output)
    return 0


def _build_plan(target_url: str, report_path: str) -> str:
    context_url = _zap.yaml_quote(_zap.context_base_url(target_url, keep_path=True))
    url = _zap.yaml_quote(target_url)
    report_file = _zap.yaml_quote(os.path.basename(report_path))
    report_dir = _zap.yaml_quote(os.path.dirname(report_path))
    return f"""env:
  contexts:
    - name: target
      urls:
        - {context_url}

jobs:
  - type: requestor
    requests:
      - url: {url}
        method: GET
        responseCode: 200

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
      reportTitle: 'ZAP Active Scan'
    risks:
      - high
      - medium
    confidences:
      - high
      - medium
"""

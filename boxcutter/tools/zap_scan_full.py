"""zap-scan-full - ZAP spider + AJAX spider + active scan. Port of app:zap-scan-full."""

from __future__ import annotations

import os
import random

from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url
from . import _zap

NAME = "zap-scan-full"
KIND = "findings"
HELP = "Full ZAP scan: spider + AJAX spider + active scan against a target URL."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--timeout", type=int, default=1200, help="Process timeout in seconds")
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    run = _zap.prepare_run()
    plan = _build_plan(target, run.report_path, run.urls_path)
    port = random.randint(20000, 40000)
    dbg(f"Target: {target}")
    cfg = _zap.replacer_configs(_zap.header_map(args.header))
    _zap.execute(run, plan, args.timeout, dbg, host="127.0.0.1", port=port, extra_config=cfg)

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


def _build_plan(target_url: str, report_path: str, urls_path: str) -> str:
    context_url = _zap.yaml_quote(_zap.context_base_url(target_url))
    url = _zap.yaml_quote(target_url)
    report_file = _zap.yaml_quote(os.path.basename(report_path))
    report_dir = _zap.yaml_quote(os.path.dirname(report_path))
    urls_file = _zap.yaml_quote(urls_path)
    includes = _zap.include_block(target_url)
    return f"""env:
  contexts:
    - name: target
      urls:
        - {context_url}{includes}

jobs:
  - type: spider
    parameters:
      context: target
      url: {url}
      maxDuration: 1

  - type: spiderAjax
    parameters:
      context: target
      url: {url}
      maxDuration: 1
      numberOfBrowsers: 1
      maxCrawlDepth: 5
      maxCrawlStates: 200
      clickDefaultElems: true
      clickElemsOnce: true
      inScopeOnly: true
      browserId: firefox-headless

  - type: activeScan
    parameters:
      context: target
      addQueryParam: false
      handleAntiCSRFTokens: true
      scanHeadersAllRequests: false
      delayInMs: 100
      threadPerHost: 2
      maxRuleDurationInMins: 1
      maxScanDurationInMins: 8
    policyDefinition:
      defaultStrength: medium
      defaultThreshold: low

  - type: report
    parameters:
      template: traditional-json
      reportDir: {report_dir}
      reportFile: {report_file}
      reportTitle: 'ZAP Full Scan'
    risks:
      - high
      - medium
    confidences:
      - high
      - medium

  - type: export
    parameters:
      context: target
      type: url
      source: all
      fileName: {urls_file}
"""

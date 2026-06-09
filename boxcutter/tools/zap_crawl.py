"""zap-crawl - crawl a URL with ZAP spider + AJAX spider. Port of app:zap-crawl."""

from __future__ import annotations

import os

from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result
from ..core.urlfilter import keep_url
from ..core.validators import is_valid_url
from . import _zap

NAME = "zap-crawl"
KIND = "urls"
HELP = "Crawl a target URL with ZAP AJAX + traditional spider."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--js", action="store_true", help="Return JS URLs only")
    parser.add_argument("--params", action="store_true", help="Return URLs with query params only")
    parser.add_argument("--timeout", type=int, default=600, help="Process timeout in seconds")
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1
    if args.js and args.params:
        output_result([], args.output, "Use either --js or --params, not both.")
        return 1

    crawled = _run_zap(target, args.timeout, dbg, args.header)

    urls: list[str] = []
    for url in crawled:
        url = url.strip()
        if not keep_url(url, args.js, args.params):
            continue
        if url not in urls:
            urls.append(url)

    output_result(urls, args.output)
    return 0


def _run_zap(target: str, timeout: int, dbg, raw_headers=None) -> list[str]:
    run = _zap.prepare_run()
    plan = _build_plan(target, run.urls_path)
    dbg(f"Target: {target}")
    cfg = _zap.replacer_configs(_zap.header_map(raw_headers))
    _zap.execute(run, plan, timeout, dbg, extra_config=cfg)

    if not os.path.exists(run.urls_path):
        dbg("URLs file was not generated.")
        _zap.cleanup(run)
        return []

    urls = _zap.read_urls(run.urls_path)
    dbg(f"Found {len(urls)} unique URLs.")
    _zap.cleanup(run)
    return urls


def _build_plan(target_url: str, urls_path: str) -> str:
    url = _zap.yaml_quote(target_url)
    urls_file = _zap.yaml_quote(urls_path)
    includes = _zap.include_block(target_url)
    return f"""env:
  contexts:
    - name: target
      urls:
        - {url}{includes}

jobs:
  - type: spider
    parameters:
      context: target
      url: {url}
      maxDuration: 2

  - type: spiderAjax
    parameters:
      context: target
      url: {url}
      maxDuration: 2
      numberOfBrowsers: 1
      maxCrawlDepth: 5
      maxCrawlStates: 200
      clickDefaultElems: true
      clickElemsOnce: true
      inScopeOnly: true
      browserId: firefox-headless

  - type: export
    parameters:
      context: target
      type: url
      source: all
      fileName: {urls_file}
"""

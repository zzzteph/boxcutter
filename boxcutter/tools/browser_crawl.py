"""browser-crawl - render and interact with a JS/SPA app to capture routes + XHR/fetch.

The raw HTTP tools fetch a SPA's empty shell; this renders it in a headless browser, records every
XHR/fetch (the real API surface), extracts same-origin routes, and clicks a bounded set of elements to
trigger more. Capability-gated: needs Playwright + Chromium (auto-pruned where unavailable).

Emits items: {url, method, type: xhr|route}.
"""

from __future__ import annotations

import os
import shutil
from urllib.parse import urlparse

from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "browser-crawl"
KIND = "items"
HELP = "Render a JS/SPA in a headless browser and capture its routes + API (XHR/fetch) calls."

_SKIP_WORDS = ("logout", "sign out", "log out", "delete", "remove", "deactivate", "pay", "purchase")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL to render")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Request header, e.g. an auth token (repeatable)")
    parser.add_argument("--timeout", type=int, default=45, help="Per-page timeout (seconds)")
    parser.add_argument("--max-actions", dest="max_actions", type=int, default=25,
                        help="Max elements to click while exploring")
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)
    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1
    try:
        from playwright.sync_api import sync_playwright
    except Exception:  # noqa: BLE001
        output_result([], args.output, "playwright is not installed (browser-crawl is a full-image tool)")
        return 1

    headers = {}
    for raw in args.header or []:
        if ":" in raw:
            k, v = raw.split(":", 1)
            headers[k.strip()] = v.strip()
    base_host = urlparse(target).hostname or ""

    def same(url):
        return (urlparse(url).hostname or "") == base_host

    captured = {}   # (method, url) -> True   (XHR/fetch)
    routes = set()

    try:
        exe = os.environ.get("CHROMIUM_PATH") or shutil.which("chromium-browser") or shutil.which("chromium")
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, **({"executable_path": exe} if exe else {}))
            ctx = browser.new_context(extra_http_headers=headers, ignore_https_errors=True)
            page = ctx.new_page()

            def on_request(req):
                if req.resource_type in ("xhr", "fetch") and same(req.url):
                    captured[(req.method, req.url.split("#")[0])] = True

            page.on("request", on_request)
            page.goto(target, wait_until="networkidle", timeout=args.timeout * 1000)

            def collect_routes():
                for href in (page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)") or []):
                    if same(href):
                        routes.add(href.split("#")[0])

            collect_routes()
            for el in (page.query_selector_all("button, [role=button], a[href]") or [])[:args.max_actions]:
                try:
                    label = (el.inner_text() or "").strip().lower()
                    if any(w in label for w in _SKIP_WORDS):
                        continue
                    el.click(timeout=2000, no_wait_after=True)
                    page.wait_for_timeout(300)
                except Exception:  # noqa: BLE001 - a click that navigates/throws is fine, keep going
                    continue
            collect_routes()
            browser.close()
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"browser-crawl failed: {exc}")
        return 1

    items = [{"url": url, "method": method, "type": "xhr"} for (method, url) in sorted(captured)]
    items += [{"url": url, "method": "GET", "type": "route"} for url in sorted(routes)]
    dbg(f"browser-crawl: {len(captured)} api calls, {len(routes)} routes")
    output_result(items, args.output)
    return 0

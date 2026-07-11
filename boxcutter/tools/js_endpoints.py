"""js-endpoints - extract API endpoints referenced inside a JS file.
Port of app:js-endpoints."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import output_result

NAME = "js-endpoints"
KIND = "items"
HELP = "Fetch a JavaScript file and extract API endpoint references via regex."

_Q = "['\"`]"  # matches ' or " or `
_P = r"[\/][a-zA-Z0-9\/_\-{}.?=&%]+"  # /path with query-ish chars

PATTERNS = [
    re.compile(rf"\bfetch\s*\(\s*{_Q}({_P}){_Q}"),
    re.compile(rf"\baxios\s*\.\s*(?:get|post|put|patch|delete|head)\s*\(\s*{_Q}({_P}){_Q}"),
    re.compile(rf"\$http\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*{_Q}({_P}){_Q}"),
    re.compile(rf"\.open\s*\(\s*{_Q}(?:GET|POST|PUT|PATCH|DELETE){_Q}\s*,\s*{_Q}({_P}){_Q}"),
    re.compile(rf"{_Q}(\/api\/[a-zA-Z0-9\/_\-{{}}.?=&%]+){_Q}"),
    re.compile(rf"(?:baseURL|BASE_URL|baseUrl)\s*[:=]\s*{_Q}([\/][a-zA-Z0-9\/_\-]+){_Q}"),
    re.compile(rf"\burl\s*:\s*{_Q}(\/[a-zA-Z0-9\/_\-{{}}.?=&%]+){_Q}"),
]

SKIP_PREFIXES = ["/css/", "/js/", "/images/", "/fonts/", "/assets/", "/media/", "/img/", "/static/"]
_VERSIONED = re.compile(r"\.[0-9a-f]{8,}\.(js|css|png|svg|woff)")


def add_arguments(parser) -> None:
    parser.add_argument("js_url", help="Full URL of the JavaScript file to scan")
    parser.add_argument("--base-url", dest="base_url", default="",
                        help="Base URL to prepend to discovered paths")
    parser.add_argument("-H", "--header", dest="header", action="append", default=[],
                        metavar="NAME: VALUE", help="Request header (repeatable) - e.g. an auth cookie so a "
                                                    "JS bundle behind a login wall is actually fetched")
    add_common_args(parser)


def run(args) -> int:
    js_url = args.js_url.strip()
    base_url = (args.base_url or "").rstrip("/")
    # Default the base to the JS file's own origin so discovered paths come out as
    # absolute, scannable URLs (a relative "/api/x" can't be fed to fuzz/sqlmap/zap).
    if not base_url:
        parts = urlparse(js_url)
        if parts.scheme and parts.netloc:
            base_url = f"{parts.scheme}://{parts.netloc}"

    headers: dict[str, str] = {}
    for raw in args.header or []:
        name, sep, value = raw.partition(":")
        if sep:
            headers[name.strip()] = value.strip()

    try:
        response = http.get(js_url, timeout=30, verify=True, headers=headers or None)
    except Exception as exc:
        output_result([], args.output, str(exc))
        return 1

    if not http.is_successful(response):
        output_result([], args.output, f"HTTP {response.status_code} fetching JS file")
        return 1

    content = response.text
    found: list[str] = []
    for pattern in PATTERNS:
        for match in pattern.finditer(content):
            path = match.group(1).strip()
            if _should_skip(path) or path in found:
                continue
            found.append(path)

    found.sort()

    source = "js:" + js_url.rsplit("/", 1)[-1]
    endpoints = [
        {"path": p, "url": (base_url + p) if base_url else p, "source": source}
        for p in found
    ]

    output_result(
        [{"url": js_url, "total": len(endpoints), "endpoints": endpoints}],
        args.output,
    )
    return 0


def _should_skip(path: str) -> bool:
    if len(path) <= 2:
        return True
    if any(path.startswith(prefix) for prefix in SKIP_PREFIXES):
        return True
    return _VERSIONED.search(path) is not None

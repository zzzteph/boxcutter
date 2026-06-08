"""http-request - make a raw HTTP request to a target. Port of app:http-request."""

from __future__ import annotations

import html
import re

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import output_result
from ..core.validators import is_valid_url

NAME = "http-request"
KIND = "items"
HELP = "Make an HTTP request to a target URL (POST if --data/-D given, else GET)."

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-D", "--data", "--D", dest="data", default=None,
                        help="POST body data (omit for GET)")
    parser.add_argument("-H", "--header", "--H", dest="header", action="append", default=[],
                        metavar="NAME: VALUE", help='Request header (repeatable)')
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    headers: dict[str, str] = {}
    for raw in args.header or []:
        parts = raw.split(":", 1)
        if len(parts) == 2:
            headers[parts[0].strip()] = parts[1].strip()

    method = "POST" if args.data is not None else "GET"

    try:
        response = http.with_retries(
            lambda: http.request(method, target, headers=headers, data=args.data, verify=True),
            retries=3, sleep_ms=200,
        )
    except Exception as exc:
        output_result([], args.output, str(exc))
        return 1

    body = response.text
    title = None
    if m := _TITLE.search(body):
        title = html.unescape(m.group(1).strip())

    flat_headers = {name: value for name, value in response.headers.items()}

    output_result(
        [{"url": target, "title": title, "status": response.status_code, "content": body, "headers": flat_headers}],
        args.output,
    )
    return 0

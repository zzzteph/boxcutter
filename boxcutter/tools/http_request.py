"""http-request - make a raw HTTP request to a target. Port of app:http-request."""

from __future__ import annotations

import hashlib
import html
import re

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import output_result
from ..core.validators import is_valid_url

NAME = "http-request"
KIND = "items"
HELP = "Make an HTTP request to a target URL (POST if --data/-D given, else GET; -X sets any method)."

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)

# Content types whose body is a real binary asset (image / font / pdf / archive / media): decoding it to text
# yields meaningless mojibake, so we NEVER inline it - we return a short descriptor instead. This matters most
# for the LLM-driven agents (joseph et al.), where an inlined image body is tens of KB of noise that carries
# zero signal AND gets re-sent on every subsequent turn - a large, pure-waste token sink.
_BINARY_CT = re.compile(
    r"^\s*(?:image|audio|video|font)/"
    r"|^\s*application/(?:octet-stream|pdf|zip|gzip|x-gzip|x-tar|x-bzip2|x-7z-compressed|x-rar-compressed|"
    r"java-archive|wasm|x-font|vnd\.ms-|msword|vnd\.openxmlformats)",
    re.I)


def _looks_binary(content_type: str, raw: bytes) -> bool:
    """A response body we must NOT inline as text - a genuine binary asset whose decoded form is noise. Decided
    by content-type first, then by a NUL byte / high control-byte ratio in a sample (so an untyped
    octet-stream image, a mislabelled asset, or a raw download is still caught)."""
    if content_type and _BINARY_CT.search(content_type):
        return True
    sample = raw[:2048]
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    nontext = sum(1 for b in sample if b < 9 or 13 < b < 32)
    return nontext / len(sample) > 0.30


def _binary_descriptor(content_type: str, raw: bytes) -> str:
    """A compact, useful stand-in for a binary body: its size, type and a short content hash - enough to
    reason about (is it an image? did it change?) without spending tokens on the bytes themselves."""
    return (f"[binary body not inlined: {len(raw)} bytes, content-type {content_type or 'unknown'}, "
            f"sha256 {hashlib.sha256(raw).hexdigest()[:16]}]")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-D", "--data", dest="data", default=None,
                        help="POST body data (omit for GET)")
    parser.add_argument("-H", "--header", dest="header", action="append", default=[],
                        metavar="NAME: VALUE", help='Request header (repeatable)')
    parser.add_argument("-X", "--method", dest="method", default=None,
                        help="HTTP method (GET/POST/PUT/PATCH/DELETE/OPTIONS/...); "
                             "default: POST if -D given, else GET. A body (-D) may accompany any method.")
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

    method = (args.method or ("POST" if args.data is not None else "GET")).upper()

    try:
        response = http.with_retries(
            lambda: http.request(method, target, headers=headers, data=args.data, verify=True),
            retries=3, sleep_ms=200,
        )
    except Exception as exc:
        output_result([], args.output, str(exc))
        return 1

    flat_headers = {name: value for name, value in response.headers.items()}

    # Never inline a binary asset (image/font/pdf/media): its decoded text is meaningless mojibake that would
    # cost tens of KB of tokens and be re-sent every turn in an agentic loop. Return a compact descriptor
    # (size + type + hash) instead - enough to reason about without spending tokens on the bytes.
    ctype = response.headers.get("Content-Type", "")
    raw = response.content or b""
    if _looks_binary(ctype, raw):
        body = _binary_descriptor(ctype, raw)
        title = None
    else:
        body = response.text
        title = None
        if m := _TITLE.search(body):
            title = html.unescape(m.group(1).strip())

    output_result(
        [{"url": target, "title": title, "status": response.status_code, "content": body, "headers": flat_headers}],
        args.output,
    )
    return 0

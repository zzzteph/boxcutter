"""extract-domains - fetch a URL and extract every DOMAIN referenced in its body.

Generic and composable: point it at a JS bundle, a source map, an HTML page, a JSON config - anything text - and
it pulls the hostnames referenced inside (API hosts, CDNs, third-party and leaked internal infra). It takes ONE
URL, so wire it after ``js-files`` (``js-files -> extract-domains``) to pull all domains out of a site's JS and
maps, then drop the noise with a ``filter`` box. KIND=urls, so it chains straight on.

Requests-only; one GET per URL.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import http
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result

NAME = "extract-domains"
KIND = "urls"
HELP = "Fetch a URL (JS/map/HTML/JSON) and extract the domains referenced in it. Chains after js-files."

_URL_HOST = re.compile(r"https?://([a-zA-Z0-9.\-]+)", re.I)
_PROTO_REL = re.compile(r"""["'(]//([a-zA-Z0-9.\-]+)""")
_FILE_TLDS = {"js", "mjs", "cjs", "css", "map", "json", "png", "svg", "ico", "jpg", "jpeg", "gif", "webp",
              "woff", "woff2", "ttf", "eot", "mp4", "html", "htm", "wasm"}
_LABEL = re.compile(r"[a-z0-9_-]{1,63}")
_TLD = re.compile(r"[a-z0-9-]{2,24}")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL to fetch and scan for domains (a JS file, map, page, JSON, ...)")
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout seconds (default 20)")
    add_header_arg(parser)
    add_common_args(parser)


def _valid_host(h: str) -> str | None:
    h = (h or "").strip().lower().strip(".")
    if "." not in h or len(h) > 253:
        return None
    labels = h.split(".")
    if labels[-1] in _FILE_TLDS or not _TLD.fullmatch(labels[-1]):
        return None
    if not all(_LABEL.fullmatch(l) for l in labels):
        return None
    return h


def hosts_in(text: str) -> set[str]:
    """Every valid hostname referenced in ``text`` (via http(s):// and protocol-relative //host)."""
    out: set[str] = set()
    for rx in (_URL_HOST, _PROTO_REL):
        for m in rx.finditer(text or ""):
            hv = _valid_host(m.group(1))
            if hv:
                out.add(hv)
    return out


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target = args.target.strip()
    headers: dict[str, str] = {}
    for raw in args.header or []:
        name, sep, value = raw.partition(":")
        if sep:
            headers[name.strip()] = value.strip()

    try:
        r = http.get(target, timeout=args.timeout, verify=True, headers=headers or None)
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"could not fetch {target}: {exc}")
        return 1
    if not http.is_successful(r):
        output_result([], args.output, f"HTTP {r.status_code} fetching {target}")
        return 1

    self_host = (urlparse(target).hostname or "").lower()
    hosts = hosts_in(r.text)
    records = [{"url": h, "domain": h, "external": h != self_host and not h.endswith("." + self_host),
                "source": target} for h in sorted(hosts)]
    dbg(f"extract-domains: {len(records)} domain(s) in {target}")
    output_result(records, args.output)
    return 0

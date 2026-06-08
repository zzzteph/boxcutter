"""url-crawl - combine Katana + ZAP crawlers. Port of app:url-crawl."""

from __future__ import annotations

from types import SimpleNamespace

from ..core import fsutil
from ..core.args import add_common_args
from ..core.envelope import dedupe, output_result, read_envelope
from ..core.validators import is_valid_url
from . import katana_crawl, zap_crawl

NAME = "url-crawl"
KIND = "urls"
HELP = "Combine Katana and ZAP crawlers for a target URL."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--js", action="store_true", help="Return JS URLs only")
    parser.add_argument("--params", action="store_true", help="Return URLs with query params only")
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1
    if args.js and args.params:
        output_result([], args.output, "Use either --js or --params, not both.")
        return 1

    katana_out = fsutil.temp_file("urlcrawl_katana_")
    zap_out = fsutil.temp_file("urlcrawl_zap_")

    katana_crawl.run(
        SimpleNamespace(
            target=target, timeout=120, js=args.js, params=args.params,
            opt_args="", output=katana_out, debug=args.debug,
        )
    )
    zap_crawl.run(
        SimpleNamespace(
            target=target, js=args.js, params=args.params, timeout=600,
            output=zap_out, debug=args.debug,
        )
    )

    katana_data = read_envelope(katana_out).get("data", []) or []
    zap_data = read_envelope(zap_out).get("data", []) or []
    fsutil.remove(katana_out)
    fsutil.remove(zap_out)

    urls = dedupe([*katana_data, *zap_data])
    output_result(urls, args.output)
    return 0

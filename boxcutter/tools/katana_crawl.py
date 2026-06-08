"""katana-crawl - crawl a target URL with Katana. Port of app:katana-crawl."""

from __future__ import annotations

from ..core import fsutil, process
from ..core.args import add_common_args, add_header_arg, add_opt_args
from ..core.envelope import debug_logger, output_result
from ..core.urlfilter import keep_url
from ..core.validators import is_valid_url

NAME = "katana-crawl"
KIND = "urls"
HELP = "Crawl a target URL with Katana (supports --js / --params filters)."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--timeout", type=int, default=120, help="Process timeout in seconds")
    parser.add_argument("--js", action="store_true", help="Return JS URLs only")
    parser.add_argument("--params", action="store_true", help="Return URLs with query params only")
    add_opt_args(parser)
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

    crawled = _run_katana(target, args.timeout, args.opt_args, getattr(args, "header", []), dbg)

    urls: list[str] = []
    for url in crawled:
        url = url.strip()
        if not keep_url(url, args.js, args.params):
            continue
        if url not in urls:
            urls.append(url)

    output_result(urls, args.output)
    return 0


def _run_katana(target: str, timeout: int, opt_args: str, headers: list[str], dbg) -> list[str]:
    tmp = fsutil.temp_file("katana_")
    cmd = [
        "katana", "-u", target, "-fsu", "-xhr", "-jc", "-jsl",
        "-sc", "-aff", "-kf", "all", "-silent", "-o", tmp,
    ]
    for header in headers:
        cmd += ["-H", header]
    cmd += process.split_opt_args(opt_args)
    dbg(f"Command: {process.format_command(cmd)}")

    result = process.run(cmd, timeout=timeout)
    if not result.successful():
        dbg("katana exited with a non-zero status.")

    output = fsutil.read_text(tmp)
    fsutil.remove(tmp)

    urls: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if line and line not in urls:
            urls.append(line)
    return urls

"""tech-detect - fingerprint a live web service via httpx. Port of app:tech-detect."""

from __future__ import annotations

import json

from ..core import fsutil, process
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "tech-detect"
KIND = "items"
HELP = "Fingerprint a live web service with httpx tech-detect (Wappalyzer)."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Live HTTP/HTTPS URL to fingerprint")
    parser.add_argument("--timeout", type=int, default=60, help="Process timeout in seconds")
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    tmp = fsutil.temp_file("techdetect_")
    cmd = [
        "httpx", "-u", target, "-tech-detect", "-title", "-server",
        "-status-code", "-follow-redirects", "-j", "-silent", "-o", tmp,
    ]
    for header in args.header:
        cmd += ["-H", header]
    dbg(f"Command: {process.format_command(cmd)}")

    process.run(cmd, timeout=args.timeout)

    raw = fsutil.read_text(tmp)
    fsutil.remove(tmp)

    results: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        results.append(
            {
                "url": data.get("url", target),
                "title": data.get("title", ""),
                "server": data.get("webserver", data.get("server", "")),
                "status": data.get("status_code", 0),
                "technologies": data.get("tech", data.get("technologies", [])),
            }
        )

    if not results:
        output_result([], args.output, "No response from target.")
        return 1

    output_result(results, args.output)
    return 0

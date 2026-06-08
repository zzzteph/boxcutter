"""dnsx - resolve a subdomain (A/AAAA/CNAME). Port of app:dnsx."""

from __future__ import annotations

import os

from ..core import fsutil, process
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result

NAME = "dnsx"
KIND = "urls"
HELP = "Resolve a subdomain using dnsx (A, AAAA, CNAME records)."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Subdomain to resolve")
    parser.add_argument("--timeout", type=int, default=90, help="Process timeout in seconds")
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    if not target:
        output_result([], args.output, "Target is empty.")
        return 1

    input_file = fsutil.temp_file("dnsx_in_")
    result_file = fsutil.temp_file("dnsx_out_")
    with open(input_file, "w", encoding="utf-8") as fh:
        fh.write(target)

    cmd = [
        "dnsx", "-duc", "-rcode", "noerror", "-silent",
        "-a", "-aaaa", "-cname", "-l", input_file, "-o", result_file,
    ]
    dbg(f"Command: {process.format_command(cmd)}")

    process.run(cmd, timeout=args.timeout)
    fsutil.remove(input_file)

    if not os.path.exists(result_file):
        output_result([], args.output, "dnsx produced no output file.")
        return 1

    raw = fsutil.read_text(result_file)
    fsutil.remove(result_file)

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    output_result(lines, args.output)
    return 0

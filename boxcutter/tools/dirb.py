"""dirb - directory brute-forcing. Port of app:dirb."""

from __future__ import annotations

import re

from ..core import fsutil, process
from ..core.args import add_common_args, add_opt_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "dirb"
KIND = "findings"
HELP = "Brute-force directories on a target URL with dirb."

DEFAULT_WORDLIST = "/usr/share/dirb/wordlists/common.txt"
# + https://example.com/admin (CODE:200|SIZE:279)
_FINDING = re.compile(r"^\+\s+(\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)$")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--wordlist", default=None, help=f"Wordlist path (default: {DEFAULT_WORDLIST})")
    parser.add_argument("--timeout", type=int, default=300, help="Process timeout in seconds")
    add_opt_args(parser)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    wordlist = args.wordlist or DEFAULT_WORDLIST
    tmp = fsutil.temp_file("dirb_")
    # Isolated cwd so dirb's resume.cfg files from concurrent runs don't collide.
    work_dir = fsutil.temp_dir("dirb_")

    cmd = ["dirb", target, wordlist, "-r", "-o", tmp]
    cmd += process.split_opt_args(args.opt_args)
    dbg(f"Command: {process.format_command(cmd)}")

    process.run(cmd, timeout=args.timeout, cwd=work_dir)

    raw = fsutil.read_text(tmp)
    fsutil.remove(tmp)
    fsutil.remove_dir(work_dir)

    findings: list[dict] = []
    for line in raw.splitlines():
        match = _FINDING.match(line.strip())
        if match:
            url, code, size = match.group(1), int(match.group(2)), int(match.group(3))
            findings.append(
                {
                    "severity": "info",
                    "title": f"path: {url}",
                    "info": f"HTTP {code}, {size} bytes",
                    "url": url,
                }
            )

    output_result(findings, args.output)
    return 0

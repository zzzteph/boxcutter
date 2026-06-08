"""dirsearch - directory brute-forcing. Port of app:dirsearch."""

from __future__ import annotations

import re

from ..core import fsutil, process
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "dirsearch"
KIND = "findings"
HELP = "Brute-force directories on a target URL with dirsearch."

DIRSEARCH = "/usr/share/dirsearch/dirsearch.py"
# 200    14B https://example.com/path  (28ms)
_FINDING = re.compile(r"^(\d{3})\s+(\d+(?:\.\d+)?)(B|KB|MB|GB)\s+(https?://\S+)", re.I)


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--timeout", type=int, default=600, help="Process timeout in seconds")
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    tmp = fsutil.temp_file("dirsearch_")
    cmd = ["python3", DIRSEARCH, "-i", "200", "--url", target, "--no-color", "-o", tmp]
    for header in args.header:
        cmd += ["-H", header]
    dbg(f"Command: {process.format_command(cmd)}")

    process.run(cmd, timeout=args.timeout)

    raw = fsutil.read_text(tmp)
    fsutil.remove(tmp)

    findings: list[dict] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        match = _FINDING.match(line.strip())
        if not match:
            continue
        url = match.group(4).rstrip()
        if url in seen:
            continue
        seen.add(url)
        code = int(match.group(1))
        size = _to_bytes(float(match.group(2)), match.group(3))
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


def _to_bytes(n: float, unit: str) -> int:
    return {
        "KB": int(n * 1024),
        "MB": int(n * 1024 * 1024),
        "GB": int(n * 1024 * 1024 * 1024),
    }.get(unit.upper(), int(n))

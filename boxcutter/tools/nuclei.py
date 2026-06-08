"""nuclei - template-based vulnerability scanner. Port of app:nuclei."""

from __future__ import annotations

import re

from ..core import fsutil, process
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result

NAME = "nuclei"
KIND = "findings"
HELP = "Run Nuclei vulnerability scanner against a target."

# [template-id] [protocol] [severity] matched-at ...
_LINE = re.compile(r"^\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(.*)$")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument(
        "--opt-args", dest="opt_args", default="",
        help="Optional nuclei flags, e.g. '-t cves -s high'",
    )
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    opt_args = args.opt_args.strip()
    dbg = debug_logger(args.debug)

    tmp = fsutil.temp_file("nuclei_")
    dbg(f"Creating tmp file: {tmp}")

    cmd = ["nuclei", "--silent", "-ni", "-o", tmp, "-u", target]
    for header in args.header:
        cmd += ["-H", header]
    cmd += process.split_opt_args(opt_args)
    dbg(f"Command: {process.format_command(cmd)}")

    result = process.run(cmd, timeout=300)
    if not result.successful():
        dbg("nuclei exited with a non-zero status.")

    output = fsutil.read_text(tmp)
    fsutil.remove(tmp)

    findings: list[dict] = []
    for line in output.splitlines():
        match = _LINE.match(line)
        if not match:
            continue
        title = match.group(1)
        severity = match.group(3)
        if severity == "critical":
            severity = "high"
        if severity not in ("low", "info", "medium", "high"):
            severity = "info"
        matched = match.group(4).split()
        findings.append(
            {
                "severity": severity,
                "title": title,
                "info": line,
                "url": matched[0] if matched else target,
            }
        )

    output_result(findings, args.output)
    return 0

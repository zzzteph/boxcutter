"""ping-scan - host discovery with nmap (which hosts are up).

Inventory a host, IP, CIDR, or range without touching any port:

    nmap -sn -oG - <target>

Emits KIND=urls: one entry per host that answered (the live host list), so it can
feed nmap (service/version scan) or the web tools. On a large range, run this first
to find the live hosts, then scan only those.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import process
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result

NAME = "ping-scan"
KIND = "urls"
HELP = "Host discovery (nmap -sn): which hosts in a target/range are up."

_UP_RE = re.compile(r"^Host:\s+(\S+)\s+\([^)]*\)\s+Status:\s+Up", re.I)


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL, hostname, IP, CIDR (10.0.0.0/24), or range (10.0.0.1-50)")
    parser.add_argument("--timeout", type=int, default=300, help="Max total seconds (default 300)")
    add_common_args(parser)


def _host(target: str) -> str:
    t = target.strip()
    return (urlparse(t).hostname or t) if "://" in t else t


def _parse(output: str) -> list[str]:
    seen: list[str] = []
    for line in output.splitlines():
        m = _UP_RE.match(line.strip())
        if m and m.group(1) not in seen:
            seen.append(m.group(1))
    return seen


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target = _host(args.target)
    if not target:
        output_result([], args.output, "Invalid target.")
        return 1

    cmd = ["nmap", "-sn", "-oG", "-", target]
    dbg(f"Command: {process.format_command(cmd)}")
    result = process.run(cmd, timeout=args.timeout)
    if not result.successful():
        dbg(f"nmap exited non-zero ({result.returncode}); parsing whatever was captured.")
    hosts = _parse(result.stdout or "")
    dbg(f"ping-scan: {len(hosts)} host(s) up")
    output_result(hosts, args.output)
    return 0

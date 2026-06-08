"""httpx - probe a target for live HTTP services. Port of app:httpx."""

from __future__ import annotations

import json

from ..core import fsutil, process
from ..core.args import add_common_args, add_header_arg, add_opt_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import has_public_ip

NAME = "httpx"
KIND = "items"
HELP = "Probe a target with httpx to detect live HTTP services."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("--timeout", type=int, default=120, help="Process timeout in seconds")
    add_opt_args(parser)
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)

    tmp = fsutil.temp_file("httpx_")
    dbg(f"Creating tmp file: {tmp}")

    cmd = ["httpx", "-u", target, "-j", "-silent", "-ip", "-o", tmp]
    for header in args.header:
        cmd += ["-H", header]
    cmd += process.split_opt_args(args.opt_args)
    dbg(f"Command: {process.format_command(cmd)}")

    result = process.run(cmd, timeout=args.timeout)
    if not result.successful():
        dbg("httpx exited with a non-zero status.")

    output = fsutil.read_text(tmp)
    fsutil.remove(tmp)

    services: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict) or "scheme" not in data or "port" not in data:
            continue

        # httpx returns 'a' as an IPv4 array and 'ip' as a single fallback.
        ips = [ip for ip in (_as_list(data.get("a")) + _as_list(data.get("ip"))) if ip]

        if ips and not has_public_ip(ips):
            dbg(
                "Skipping internal host: "
                f"{data.get('url') or data.get('input') or ''} -> {', '.join(ips)}"
            )
            continue

        services.append(
            {
                "port": data["port"],
                "scheme": data["scheme"],
                "url": data.get("url")
                or f"{data['scheme']}://{data.get('input', '')}:{data['port']}",
                "ip": ", ".join(ips),
                "version": data.get("version", ""),
            }
        )

    output_result(services, args.output)
    return 0


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]

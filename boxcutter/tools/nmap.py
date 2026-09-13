"""nmap - TCP service/version scan of a host, IP, or range.

Pass a URL, hostname, IP, CIDR, or nmap range and get back one row per open port:
IP, PORT, and detected VERSION. Runs a connect scan with version detection:

    nmap -sT --open -Pn -sV -p <ports> -oG - <target>

Emits KIND=endpoints. Each row is {ip, host, port, protocol, service, version, url};
`url` is filled for web services (http/https), so the endpoint list can feed the
URL-based tools directly.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import process
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result

NAME = "nmap"
KIND = "endpoints"
HELP = "TCP service/version scan (nmap -sT --open -Pn -sV): a host/IP/range -> open ports with versions."

# A broad-but-bounded default port set: common web + service ports. Override with --ports.
_DEFAULT_PORTS = ("21,22,23,25,53,80,110,111,135,139,143,161,443,445,993,995,1433,1521,"
                  "1723,2049,3000,3306,3389,5000,5432,5900,5985,6379,8000,8008,8080,8081,"
                  "8443,8888,9000,9092,9200,9300,11211,27017")

_HTTPS_PORTS = {443, 8443, 9443, 4443}
_HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888, 3000, 5000, 9000}
# a greppable "Host:" line carrying the Ports field
_HOST_RE = re.compile(r"^Host:\s+(\S+)\s+\(([^)]*)\)\s+.*?Ports:\s+(.+?)(?:\s+Ignored State:.*)?$")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL, hostname, IP, CIDR (10.0.0.0/24), or range (10.0.0.1-50)")
    parser.add_argument("--ports", default=None,
                        help="Ports to scan, e.g. '80,443' or '1-65535' (default: a common web+service set; "
                             "an explicit port in a URL like host:12345 is used when --ports is omitted)")
    parser.add_argument("--top-ports", dest="top_ports", type=int, default=None,
                        help="Scan nmap's top-N ports instead of --ports")
    parser.add_argument("--timeout", type=int, default=600, help="Max total seconds (default 600)")
    add_common_args(parser)


def _resolve(args) -> tuple[str, list[str]]:
    """Return (host, port_flags). A URL collapses to its host, but its explicit port
    is honored: `host:12345` scans 12345 unless --ports/--top-ports override. --ports
    wins when given; else the URL port; else the default set."""
    raw = args.target.strip()
    if "://" in raw:
        u = urlparse(raw)
        host, url_port = (u.hostname or raw), u.port
    else:
        host, url_port = raw, None
    if args.top_ports:
        return host, ["--top-ports", str(args.top_ports)]
    ports = args.ports or (str(url_port) if url_port else _DEFAULT_PORTS)
    return host, ["-p", ports]


def _scheme_for(port: int, service: str) -> str:
    s = service.lower()
    if "https" in s or "ssl" in s or port in _HTTPS_PORTS:
        return "https"
    if "http" in s or port in _HTTP_PORTS:
        return "http"
    return ""


def _parse(output: str) -> list[dict]:
    endpoints: list[dict] = []
    for line in output.splitlines():
        m = _HOST_RE.match(line.strip())
        if not m:
            continue
        ip, host, ports = m.group(1), m.group(2), m.group(3)
        for chunk in ports.split(", "):
            f = chunk.split("/")
            if len(f) < 3 or f[1] != "open":
                continue
            try:
                port = int(f[0])
            except ValueError:
                continue
            service = f[4] if len(f) > 4 else ""
            version = f[6].strip() if len(f) > 6 else ""
            scheme = _scheme_for(port, service)
            endpoints.append({
                "ip": ip,
                "host": host or "",
                "port": port,
                "protocol": f[2] or "tcp",
                "service": service,
                "version": version,
                "url": f"{scheme}://{host or ip}:{port}" if scheme else "",
            })
    return endpoints


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target, port_flags = _resolve(args)
    if not target:
        output_result([], args.output, "Invalid target.")
        return 1

    cmd = ["nmap", "-sT", "--open", "-Pn", "-sV", "-oG", "-", *port_flags, target]
    dbg(f"Command: {process.format_command(cmd)}")

    result = process.run(cmd, timeout=args.timeout)
    if not result.successful():
        dbg(f"nmap exited non-zero ({result.returncode}); parsing whatever was captured.")
    endpoints = _parse(result.stdout or "")
    dbg(f"nmap: {len(endpoints)} open port(s)")
    output_result(endpoints, args.output)
    return 0

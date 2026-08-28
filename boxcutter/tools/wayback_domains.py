"""wayback-domains - derive unique hosts from app:wayback. Port of app:wayback-domains."""

from __future__ import annotations

from urllib.parse import urlparse

from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.runner import run_tool
from . import wayback

NAME = "wayback-domains"
KIND = "urls"
HELP = "Run wayback (subdomains on) and extract the unique host list."


def add_arguments(parser) -> None:
    parser.add_argument("domain", help="Domain to query, e.g. example.com")
    parser.add_argument("--timeout", type=int, default=60, help="Per-provider HTTP timeout in seconds")
    add_common_args(parser)


def run(args) -> int:
    domain = args.domain.strip().lower()
    timeout = max(5, args.timeout)
    dbg = debug_logger(args.debug)

    if not domain:
        output_result([], args.output, "Empty domain.")
        return 1

    # Drive wayback in-process via run_tool: it parses wayback's OWN argparse (so every flag/default is set -
    # no hand-built namespace to drift out of sync with wayback's arguments) and returns a JSON envelope
    # regardless of the outer --output/--table. --inc-subdomains widens to subdomains; --all keeps static-asset
    # URLs so a host that only ever served a .css is still discovered as a subdomain.
    argv = [domain, "--inc-subdomains", "--all", "--timeout", str(timeout)]
    if args.debug:
        argv.append("--debug")
    envelope = run_tool(wayback, argv)

    if not envelope.get("success", False):
        output_result([], args.output, envelope.get("error") or "wayback failed")
        return 1

    seen: dict[str, bool] = {}
    for url in envelope.get("data", []) or []:
        host = urlparse(str(url)).hostname
        if not host:
            continue
        host = host.lower()
        if host == domain or host.endswith("." + domain):
            seen[host] = True

    hosts = sorted(seen.keys())
    dbg(f"Total unique hosts: {len(hosts)}")
    output_result(hosts, args.output)
    return 0

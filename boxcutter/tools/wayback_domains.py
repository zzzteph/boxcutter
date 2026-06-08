"""wayback-domains - derive unique hosts from app:wayback. Port of app:wayback-domains."""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlparse

from ..core import fsutil
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result, read_envelope
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

    tmp = fsutil.temp_file("wayback_domains_")
    wayback.run(
        SimpleNamespace(
            domain=domain, timeout=timeout, inc_subdomains=True,
            js=False, params=False, output=tmp, debug=args.debug,
        )
    )
    envelope = read_envelope(tmp)
    fsutil.remove(tmp)

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

"""dns-brute - subdomain brute-force with a bundled default wordlist (wraps dnsx).

Convenience over `dnsx --domain <d> --wordlist <FILE>`: give just the domain and it resolves
``<word>.<domain>`` for every word in boxcutter's bundled subdomain wordlist (``data/subdomains.txt``),
overridable with --wordlist. --resp appends the resolved A/CNAME record to each line.

Wildcard-DNS filtering (dnsx ``-wd``) is chosen with --wildcard:
  smart (default) - run WITH -wd, but if it removes EVERY result, retry WITHOUT it and return that set.
                    Keeps wildcard noise out normally, yet never returns nothing just because the real
                    hosts share the wildcard's IP (common behind a CDN like Cloudflare - the weakpass.com case).
  on              - always filter (return the -wd result even when it is empty).
  off             - never filter.
The envelope's ``extra.wildcard`` reports which pass produced the results (and whether smart fell back).
"""

from __future__ import annotations

import os

from . import dnsx
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result

NAME = "dns-brute"
KIND = "urls"
HELP = ("Brute-force a domain's subdomains with boxcutter's bundled wordlist (wraps dnsx). "
        "Give just the domain; --wordlist overrides the default.")

# Bundled default wordlist - ships in the image (COPY boxcutter -> /opt/boxcutter/boxcutter).
DEFAULT_WORDLIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "subdomains.txt")


def add_arguments(parser) -> None:
    parser.add_argument("domain", help="Base domain to brute-force (e.g. example.com)")
    parser.add_argument("--wordlist", metavar="FILE", default=None,
                        help="subdomain wordlist (default: boxcutter's bundled subdomains.txt)")
    parser.add_argument("--wildcard", choices=["smart", "on", "off"], default="smart",
                        help="wildcard-DNS filtering (dnsx -wd): 'smart' (default) filters but falls back to "
                             "unfiltered when -wd removes ALL results (the CDN case); 'on' always filters; "
                             "'off' never filters")
    parser.add_argument("--resp", action="store_true", help="append the resolved A/CNAME record to each line")
    parser.add_argument("--rate", type=int, default=0, help="max DNS queries/sec (0 = dnsx default)")
    parser.add_argument("--timeout", type=int, default=300, help="Process timeout in seconds")
    add_common_args(parser)


def run(args) -> int:
    dbg = debug_logger(args.debug)
    wordlist = args.wordlist or DEFAULT_WORDLIST
    if not os.path.isfile(wordlist):
        output_result([], args.output, f"wordlist not found: {wordlist}")
        return 1

    def _brute(wildcard: bool):
        return dnsx.brute(args.domain, wordlist, wildcard=wildcard, resp=args.resp,
                          rate=args.rate, timeout=args.timeout, dbg=dbg)

    if args.wildcard == "off":
        lines, note = _brute(False), "off"
    elif args.wildcard == "on":
        lines, note = _brute(True), "on"
    else:                                        # smart
        lines = _brute(True)
        if lines or lines is None:               # -wd kept something (or hard-failed): use as-is
            note = "on"
        else:                                    # -wd removed every result: fall back to unfiltered
            dbg("wildcard (-wd) removed all results; retrying without it")
            lines, note = _brute(False), "off (fell back: -wd removed all results)"

    if lines is None:
        output_result([], args.output, "dnsx produced no output file.")
        return 1
    dbg(f"dns-brute: {len(lines)} resolved (wildcard {note})")
    output_result(lines, args.output, extra={"domain": args.domain, "wildcard": note, "count": len(lines)})
    return 0

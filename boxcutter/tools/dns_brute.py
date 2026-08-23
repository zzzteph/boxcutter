"""dns-brute - subdomain brute-force with a bundled default wordlist (wraps dnsx).

Convenience over `dnsx --domain <d> --wordlist <FILE>`: give just the domain and it resolves
``<word>.<domain>`` for every word in boxcutter's bundled subdomain wordlist (``data/subdomains.txt``),
overridable with --wordlist. Wildcard-DNS false positives are filtered by default (--no-wildcard turns
that off, and --resp appends the resolved A/CNAME record to each line).
"""

from __future__ import annotations

import argparse
import os

from . import dnsx
from ..core.args import add_common_args
from ..core.envelope import output_result

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
    parser.add_argument("--no-wildcard", dest="wildcard", action="store_false",
                        help="do NOT filter wildcard-DNS false positives (filtering is ON by default)")
    parser.add_argument("--resp", action="store_true", help="append the resolved A/CNAME record to each line")
    parser.add_argument("--rate", type=int, default=0, help="max DNS queries/sec (0 = dnsx default)")
    parser.add_argument("--timeout", type=int, default=300, help="Process timeout in seconds")
    add_common_args(parser)


def run(args) -> int:
    wordlist = args.wordlist or DEFAULT_WORDLIST
    if not os.path.isfile(wordlist):
        output_result([], args.output, f"wordlist not found: {wordlist}")
        return 1
    # Delegate to dnsx in BRUTE mode so the resolve/wildcard/parse logic lives in one place.
    return dnsx.run(argparse.Namespace(
        target=None, listfile=None,
        domain=args.domain, wordlist=wordlist,
        wildcard=args.wildcard, resp=args.resp, rate=args.rate,
        timeout=args.timeout, output=args.output, debug=args.debug,
    ))

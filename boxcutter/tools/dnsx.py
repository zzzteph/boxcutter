"""dnsx - resolve names (A/AAAA/CNAME), brute-force a domain, and filter wildcard DNS. Port of app:dnsx, extended.

Modes (pick one):
  dnsx sub.example.com                         # resolve ONE name (original behaviour)
  dnsx --list names.txt                        # resolve a FILE of names
  dnsx --domain example.com --wordlist subs.txt  # BRUTE: resolve <word>.example.com for each word
Add --wildcard (with --domain, or a base inferred from the names) to DROP wildcard-DNS false positives, and --resp to
include the resolved A/CNAME record on each line (host [A] 1.2.3.4  /  host [CNAME] target)."""

from __future__ import annotations

import os

from ..core import fsutil, process
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result

NAME = "dnsx"
KIND = "urls"
HELP = ("Resolve names, brute-force a domain (--domain --wordlist), and filter wildcards (--wildcard). "
        "A/AAAA/CNAME; --resp adds the record.")


def add_arguments(parser) -> None:
    parser.add_argument("target", nargs="?", help="A single subdomain to resolve (or use --list / --domain+--wordlist)")
    parser.add_argument("--list", dest="listfile", metavar="FILE", help="resolve a file of names (one per line)")
    parser.add_argument("--domain", help="base domain to brute-force (with --wordlist)")
    parser.add_argument("--wordlist", metavar="FILE", help="subdomain wordlist for brute mode (with --domain)")
    parser.add_argument("--wildcard", action="store_true",
                        help="drop wildcard-DNS false positives (uses --domain, else infers the base from the names)")
    parser.add_argument("--resp", action="store_true", help="append the resolved A/CNAME record to each line")
    parser.add_argument("--rate", type=int, default=0, help="max DNS queries/sec (0 = dnsx default)")
    parser.add_argument("--timeout", type=int, default=120, help="Process timeout in seconds")
    add_common_args(parser)


def _base_domain(name: str) -> str:
    """Registrable-ish base: last two labels (best-effort; fine for wildcard calibration)."""
    parts = (name or "").strip().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def run(args) -> int:
    dbg = debug_logger(args.debug)
    cmd = ["dnsx", "-duc", "-rcode", "noerror", "-silent", "-a", "-aaaa", "-cname"]
    tmp_in = None

    if args.domain and args.wordlist:                      # BRUTE mode
        if not os.path.isfile(args.wordlist):
            output_result([], args.output, f"wordlist not found: {args.wordlist}")
            return 1
        cmd += ["-d", args.domain, "-w", args.wordlist]
        wd_base = args.domain
    elif args.listfile:                                    # resolve a FILE
        if not os.path.isfile(args.listfile):
            output_result([], args.output, f"list not found: {args.listfile}")
            return 1
        cmd += ["-l", args.listfile]
        wd_base = args.domain or _base_domain(next((ln.strip() for ln in open(args.listfile, encoding="utf-8")
                                                    if ln.strip()), ""))
    elif args.target and args.target.strip():              # single name (original behaviour)
        tmp_in = fsutil.temp_file("dnsx_in_")
        with open(tmp_in, "w", encoding="utf-8") as fh:
            fh.write(args.target.strip())
        cmd += ["-l", tmp_in]
        wd_base = args.domain or _base_domain(args.target)
    else:
        output_result([], args.output, "Nothing to resolve (give a name, --list FILE, or --domain+--wordlist).")
        return 1

    if args.wildcard and wd_base:
        cmd += ["-wd", wd_base]                            # dnsx wildcard filtering
    if args.resp:
        cmd += ["-resp"]
    if args.rate and args.rate > 0:
        cmd += ["-rl", str(args.rate)]

    result_file = fsutil.temp_file("dnsx_out_")
    cmd += ["-o", result_file]
    dbg(f"Command: {process.format_command(cmd)}")

    process.run(cmd, timeout=args.timeout)
    if tmp_in:
        fsutil.remove(tmp_in)

    if not os.path.exists(result_file):
        output_result([], args.output, "dnsx produced no output file.")
        return 1
    raw = fsutil.read_text(result_file)
    fsutil.remove(result_file)

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    dbg(f"dnsx: {len(lines)} resolved line(s)")
    output_result(lines, args.output)
    return 0

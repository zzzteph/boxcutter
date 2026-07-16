"""path-fuzz - brute-force a single FUZZ position in a URL with a wordlist.

Fuzzes ONE position (the FUZZ marker) - it does NOT crawl or recurse (that is `path-bust`'s job). The shared
content/structure soft-404 gate (boxcutter.core.soft404) keeps only real, structurally-distinct paths, so a
catch-all / soft-404 / front-controller can't produce false positives. Reports HTTP 200 by default; widen with
--codes. Default wordlist is the curated bug-bounty list; --full swaps in the big breadth list, --wordlist your own.
"""

from __future__ import annotations

import os
import time

from ..core import http, soft404
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url
from ..data.path_wordlist import WORDS

NAME = "path-fuzz"
KIND = "findings"
HELP = "Brute-force a FUZZ position in a URL; content/structure gate keeps only real, distinct paths (200 by default)."

_FULL_WORDLIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlist.txt")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL template with a FUZZ marker, e.g. https://x/api/FUZZ")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Extra header (repeatable)")
    parser.add_argument("--full", action="store_true",
                        help="Use the big breadth wordlist (data/wordlist.txt, ~12k) instead of the curated list; "
                             "much slower - consider raising --timeout")
    parser.add_argument("--wordlist", default=None, metavar="FILE",
                        help="Custom wordlist (one per line, # comments); overrides --full and the built-in list")
    parser.add_argument("--extensions", default="", metavar="php,bak,...",
                        help="Append each extension to every word (e.g. php,bak,old)")
    parser.add_argument("--codes", default="200", metavar="200,301,...",
                        help="HTTP codes to report as found (default: 200 only)")
    parser.add_argument("--timeout", type=int, default=300, help="Max total seconds")
    add_common_args(parser)


def _parse_headers(raw: list) -> dict:
    headers: dict = {}
    for item in raw or []:
        if ":" in item:
            name, value = item.split(":", 1)
            if name.strip():
                headers[name.strip()] = value.strip()
    return headers


def _read_file(path, dbg):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [w.strip() for w in fh if w.strip() and not w.lstrip().startswith("#")]


def _load_words(args, dbg) -> list:
    # Precedence: explicit --wordlist FILE > --full (breadth list) > curated built-in.
    if args.wordlist:
        try:
            words = _read_file(args.wordlist, dbg)
            dbg(f"Loaded {len(words)} words from {args.wordlist}")
        except OSError as exc:
            dbg(f"Could not read {args.wordlist} ({exc}); falling back to the curated built-in list")
            words = list(WORDS)
    elif args.full:
        try:
            words = _read_file(_FULL_WORDLIST, dbg)
            dbg(f"--full: loaded {len(words)} words from the breadth list ({_FULL_WORDLIST})")
        except OSError as exc:
            dbg(f"--full requested but could not read {_FULL_WORDLIST} ({exc}); using the curated built-in list")
            words = list(WORDS)
    else:
        words = list(WORDS)
        dbg(f"Using the curated built-in list ({len(words)} words); pass --full for the ~12k breadth list")
    exts = [e.strip().lstrip(".") for e in (args.extensions or "").split(",") if e.strip()]
    if exts:
        words = [w for base in words for w in (base, *(f"{base}.{e}" for e in exts))]
    return list(dict.fromkeys(words))


def run(args) -> int:
    template = args.target.strip()
    method = args.method.strip().upper()
    dbg = debug_logger(args.debug)
    headers = _parse_headers(args.header)

    if "FUZZ" not in template:
        output_result([], args.output, "URL template must contain a FUZZ marker.")
        return 1
    if not is_valid_url(template.replace("FUZZ", "")):
        output_result([], args.output, "Invalid URL template.")
        return 1

    words = _load_words(args, dbg)
    codes = soft404.parse_codes(args.codes)
    sess = http.session(headers)
    deadline = time.time() + args.timeout
    dbg(f"Template: {template} | method: {method} | words: {len(words)} | report codes: {sorted(codes)}")

    findings, _dirs = soft404.scan(lambda w: template.replace("FUZZ", w), method, words, sess, deadline, codes, dbg)
    findings = soft404.dedup(findings)
    dbg(f"Found {len(findings)} distinct path(s) (of {len(words)} words).")
    output_result(findings, args.output)
    return 0

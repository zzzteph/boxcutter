"""path-bust - directory brute-force UNDER a given URL path (no FUZZ marker).

Point it at a base and it appends words to that path:
    path-bust https://test.com          -> tests https://test.com/<word>
    path-bust https://test.com/admin    -> tests https://test.com/admin/<word>

Uses the shared content/structure soft-404 gate (boxcutter.core.soft404), so a catch-all / soft-404 / SPA
front-controller can't produce false positives, and RE-CALIBRATES for every directory (a subdir can 404
differently than root). Recurses into discovered directories with --depth. Reports HTTP 200 by default (widen
with --codes). Default wordlist is the curated list (fast); --full swaps in the ~12k breadth list, --wordlist
your own.
"""

from __future__ import annotations

import os
import time

from ..core import http, soft404
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url
from ..data.path_wordlist import WORDS

NAME = "path-bust"
KIND = "findings"
HELP = "Directory brute-force under a URL path (no FUZZ marker); content/structure gate, per-dir calibration, --depth."

_FULL_WORDLIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "wordlist.txt")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Base URL/host to bust under, e.g. https://x or https://x/admin")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Extra header (repeatable)")
    parser.add_argument("--full", action="store_true",
                        help="Use the big breadth wordlist (data/wordlist.txt, ~12k) instead of the curated list; "
                             "much slower - raise --timeout and expect a long run")
    parser.add_argument("--wordlist", default=None, metavar="FILE",
                        help="Custom wordlist (one per line, # comments); overrides --full and the built-in list")
    parser.add_argument("--extensions", default="", metavar="php,bak,...",
                        help="Append each extension to every word (e.g. php,bak,old)")
    parser.add_argument("--codes", default="200", metavar="200,301,...",
                        help="HTTP codes to report as found (default: 200 only)")
    parser.add_argument("--depth", type=int, default=0,
                        help="Recurse into discovered directories to this depth (0 = off); each subdir is "
                             "re-calibrated for its own catch-all")
    parser.add_argument("--timeout", type=int, default=1200,
                        help="Hard cap on TOTAL seconds across all directories (recursion shares this budget); "
                             "on expiry it returns what was found so far. Default 1200 (20 min)")
    add_common_args(parser)


def _parse_headers(raw: list) -> dict:
    headers: dict = {}
    for item in raw or []:
        if ":" in item:
            name, value = item.split(":", 1)
            if name.strip():
                headers[name.strip()] = value.strip()
    return headers


def _read_file(path) -> list:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [w.strip() for w in fh if w.strip() and not w.lstrip().startswith("#")]


def _load_words(args, dbg) -> list:
    # Precedence: explicit --wordlist FILE > --full (breadth list) > curated built-in.
    if args.wordlist:
        try:
            words = _read_file(args.wordlist)
            dbg(f"Loaded {len(words)} words from {args.wordlist}")
        except OSError as exc:
            dbg(f"Could not read {args.wordlist} ({exc}); falling back to the curated built-in list")
            words = list(WORDS)
    elif args.full:
        try:
            words = _read_file(_FULL_WORDLIST)
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
    target = args.target.strip()
    method = args.method.strip().upper()
    dbg = debug_logger(args.debug)
    headers = _parse_headers(args.header)

    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    if not is_valid_url(base_url):
        output_result([], args.output, "Invalid target URL.")
        return 1

    words = _load_words(args, dbg)
    codes = soft404.parse_codes(args.codes)
    depth = max(0, args.depth)
    sess = http.session(headers)
    deadline = time.time() + args.timeout
    dbg(f"Base: {base_url} | method: {method} | words: {len(words)} | report codes: {sorted(codes)} | depth: {depth}")
    # Honest ETA: one pass = ~len(words) sequential requests; recursion multiplies this. Warn if it can't fit.
    lo, hi = len(words) * 0.03, len(words) * 0.08
    dbg(f"ETA: one directory pass is ~{len(words)} requests (~{lo:.0f}-{hi:.0f}s at 30-80 ms each)"
        + (f"; --depth {depth} runs another full pass per discovered directory" if depth else "")
        + f". Hard cap --timeout={args.timeout}s.")
    if lo > args.timeout:
        dbg(f"WARNING: even a single pass likely exceeds --timeout={args.timeout}s - raise --timeout or use a "
            f"smaller --wordlist, or results will be partial.")

    findings, seen_urls, visited = [], set(), set()
    queue, max_dirs = [(base_url.rstrip("/"), depth)], 80
    while queue:
        if time.time() >= deadline:
            dbg(f"Hard timeout ({args.timeout}s) reached after {len(visited)} director(y/ies); "
                f"{len(queue)} still queued. Returning partial results - raise --timeout to go further.")
            break
        base, d = queue.pop(0)
        if base in visited:
            continue
        visited.add(base)
        if len(visited) > 1:
            dbg(f"-> recursing into {base}/ (depth left {d})")
        fnds, dirs = soft404.scan(lambda w, b=base: f"{b}/{w}", method, words, sess, deadline, codes, dbg)
        for f in fnds:
            if f["url"] not in seen_urls:
                seen_urls.add(f["url"])
                findings.append(f)
        if d > 0 and len(visited) < max_dirs:
            for w in dirs:
                child = f"{base}/{w.rstrip('/')}"
                if child not in visited:
                    queue.append((child, d - 1))

    findings = soft404.dedup(findings)
    dbg(f"Found {len(findings)} distinct path(s) across {len(visited)} director(y/ies).")
    output_result(findings, args.output)
    return 0

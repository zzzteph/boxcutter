"""smart-enum - turn a handful of OBSERVED URLs into a CLEVER, context-aware candidate path list.

A generic wordlist knows nothing about the app in front of you. smart-enum takes the URLs you have actually seen
(from the browser, Burp, a crawl) and derives the rest of the family the way an experienced tester would: it brute
the wordlist UNDER the prefixes/versions the app really uses, pivots the API version (v1<->v2/v3), walks numeric ids
(BOLA/IDOR), and toggles singular/plural of each observed resource. The output is a candidate list you feed to
path-bust / api-map / ffuf - far higher hit-rate per request than a blind list.

It does NOT touch the target (pure generation) - so it is safe to run anywhere and pipe its output into a scanner.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

from ..core.args import add_common_args
from ..core.envelope import output_result
from .api_map import _clever_candidates, _load_api_words, _norm

NAME = "smart-enum"
KIND = "items"
HELP = ("Generate a context-aware candidate path list from observed URLs (version pivots, numeric id-walks, "
        "singular/plural, high-value siblings under observed prefixes). Non-touching; pipe into path-bust/api-map/ffuf.")


def add_arguments(parser) -> None:
    parser.add_argument("--urls", required=True, metavar="CSV|FILE",
                        help="observed URLs or paths that seed the derivation (comma-list OR a file, one per line)")
    parser.add_argument("--wordlist", default=None,
                        help="base wordlist to brute under observed prefixes (default: the built-in API-routes list)")
    parser.add_argument("--max", dest="max_paths", type=int, default=500, help="cap generated candidates (default 500)")
    add_common_args(parser)


def _read_list(spec):
    if not spec:
        return []
    if os.path.isfile(spec):
        try:
            return [ln.strip() for ln in open(spec, encoding="utf-8") if ln.strip() and not ln.startswith("#")]
        except OSError:
            return []
    return [p.strip() for p in spec.split(",") if p.strip()]


def run(args) -> int:
    raw = _read_list(args.urls)
    if not raw:
        output_result([], args.output, "No seed URLs/paths given (--urls).")
        return 1
    # accept full URLs or bare paths; derive the path component to seed from
    fed = []
    for u in raw:
        p = urlparse(u).path if u.startswith(("http://", "https://")) else u
        fed.append(_norm(p or "/"))
    words = _read_list(args.wordlist) if args.wordlist else _load_api_words()
    cands = _clever_candidates(fed, words, max(1, args.max_paths))
    # keep observed-path derivations first, dedup, cap
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c); out.append(c)
        if len(out) >= max(1, args.max_paths):
            break
    findings = [{"path": c, "info": "candidate (derived from observed URLs)"} for c in out]
    output_result(findings, args.output)
    return 0

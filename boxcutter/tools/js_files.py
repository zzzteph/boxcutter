"""js-files - enumerate a page's JavaScript files and their SOURCE MAPS.

Fetches a target page, lists every ``<script src>`` it loads, and for each bundle derives its source map - from
the bundle's own ``//# sourceMappingURL=`` pointer and the conventional ``<file>.js.map`` - then checks whether
that map is actually reachable. An exposed ``.map`` hands an attacker the un-minified original source (routes,
secrets, comments), so this is prime disclosure recon. Emits one record per JS and per map ({url, type, status,
exposed}); KIND=urls so you can pipe maps into http-request / scan-secrets or the findings boxes.

Requests-only; reads the statically referenced scripts on the page (pair with a crawler for runtime chunks).
"""
from __future__ import annotations

import concurrent.futures
import re
from urllib.parse import urljoin

from ..core import http
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result

NAME = "js-files"
KIND = "urls"
HELP = "List a page's JS files and their source maps (.map), flagging which maps are exposed (reachable)."

_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
_SMAP = re.compile(r"""//[#@]\s*sourceMappingURL\s*=\s*(\S+)""")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Page URL to enumerate JS + source maps for")
    parser.add_argument("--max-files", dest="max_files", type=int, default=60,
                        help="Max JS files to inspect (default 60)")
    parser.add_argument("--no-verify", dest="no_verify", action="store_true",
                        help="Don't HTTP-check the derived .map URLs (just list the candidates)")
    parser.add_argument("--timeout", type=int, default=20, help="Per-request timeout seconds (default 20)")
    add_header_arg(parser)
    add_common_args(parser)


def _headers(raw_list) -> dict:
    out: dict[str, str] = {}
    for raw in raw_list or []:
        name, sep, value = raw.partition(":")
        if sep:
            out[name.strip()] = value.strip()
    return out


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target = args.target.strip()
    headers = _headers(args.header)

    try:
        page = http.get(target, timeout=args.timeout, verify=True, headers=headers or None)
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"could not fetch {target}: {exc}")
        return 1
    html = page.text if http.is_successful(page) else ""

    js_urls: list[str] = []
    seen: set[str] = set()
    for m in _SRC.finditer(html):
        u = urljoin(target, m.group(1).strip())
        if u.lower().split("?")[0].endswith((".js", ".mjs", ".cjs")) and u not in seen:
            seen.add(u)
            js_urls.append(u)
    js_urls = js_urls[: max(1, args.max_files)]
    dbg(f"js-files: {len(js_urls)} script(s) on {target}")

    # each JS -> its candidate map URL(s): the in-file sourceMappingURL pointer + the <file>.map convention
    map_candidates: dict[str, str] = {}      # map_url -> the js it came from

    def _maps_for(u: str) -> list[str]:
        cands = [u.split("?")[0] + ".map"]           # convention
        try:
            r = http.get(u, timeout=args.timeout, verify=True, headers=headers or None)
            if http.is_successful(r):
                mm = _SMAP.search(r.text or "")
                if mm:
                    ref = mm.group(1).strip()
                    if not ref.startswith("data:"):  # inline base64 map -> nothing to fetch
                        cands.insert(0, urljoin(u, ref))
        except Exception:  # noqa: BLE001
            pass
        return cands

    workers = max(1, min(len(js_urls) or 1, 10))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for u, cands in zip(js_urls, ex.map(_maps_for, js_urls)):
            for c in cands:
                map_candidates.setdefault(c, u)

    # verify the maps (reachable == exposed source) unless --no-verify
    def _check(mu: str) -> tuple[str, int, bool]:
        if args.no_verify:
            return mu, 0, False
        try:
            r = http.get(mu, timeout=args.timeout, verify=True, headers=headers or None)
            return mu, r.status_code, http.is_successful(r)
        except Exception:  # noqa: BLE001
            return mu, 0, False

    records: list[dict] = [{"url": u, "type": "js"} for u in js_urls]
    if map_candidates:
        wk = max(1, min(len(map_candidates), 10))
        with concurrent.futures.ThreadPoolExecutor(max_workers=wk) as ex:
            for mu, status, ok in ex.map(_check, list(map_candidates)):
                rec = {"url": mu, "type": "map", "from": map_candidates[mu]}
                if not args.no_verify:
                    rec["status"] = status
                    rec["exposed"] = ok
                # list all candidates when not verifying; when verifying, keep only reachable maps
                if args.no_verify or ok:
                    records.append(rec)

    exposed = sum(1 for r in records if r.get("type") == "map" and r.get("exposed"))
    dbg(f"js-files: {len(js_urls)} JS, {sum(1 for r in records if r['type']=='map')} map(s)"
        + (f", {exposed} exposed" if not args.no_verify else ""))
    output_result(records, args.output)
    return 0

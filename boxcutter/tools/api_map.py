"""api-map - method-aware API endpoint discovery.

path-bust brute-forces paths with ONE method (GET); endpoints that only answer POST/PUT/PATCH/DELETE - the write /
state-changing surface where mass-assignment, BOLA-write and business-logic vulns live - stay invisible. api-map
enumerates candidate paths x the full method set, diffs each response against a PER-METHOD catch-all baseline
(reusing the soft-404 engine), and reports which paths exist for which verbs (write verbs first).

NON-DESTRUCTIVE by design: OPTIONS first (its Allow header enumerates verbs with ZERO side-effects); POST/PUT/PATCH
send an EMPTY body only (a 400/401/403/422 already proves the endpoint exists - no valid mutation data is ever
sent, so nothing is created/changed); DELETE is NEVER invoked on a real path (its support is inferred from OPTIONS
Allow + a 405 on another verb). Run it WITH the caller's auth header(s) so an API behind a blanket 401 is still
mappable.
"""
from __future__ import annotations

import concurrent.futures as cf
import os
import re
import time
from urllib.parse import urlparse

from ..core import http, soft404
from ..core import repro as repro_mod
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result

try:
    from ..data.path_wordlist import WORDS
except Exception:  # noqa: BLE001
    WORDS = []


def _load_api_words():
    """Frequency-ranked API path segments (from the httparchive API-routes corpus), most-common first, so the
    top-N probed (bounded by --max-paths) are the highest-value routes. Falls back to the curated path wordlist."""
    p = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "api_wordlist.txt")
    if os.path.isfile(p):
        try:
            return [ln.strip() for ln in open(p, encoding="utf-8") if ln.strip() and not ln.startswith("#")]
        except OSError:
            pass
    return list(WORDS)


# generic fallback shapes (absolute, slash-terminated) used ONLY when nothing has been discovered yet.
_SHAPES = ("/", "/api/", "/api/v1/", "/v1/", "/api/v2/")

# high-value REST action/resource words tried FIRST under an OBSERVED prefix (the frequency corpus buries siblings
# like `register` at rank ~389, so a bare freq-walk misses them). These are the routes that actually matter.
_HIGH_VALUE = (
    "me", "profile", "account", "user", "users", "admin", "login", "logout", "register", "signup", "refresh",
    "token", "session", "auth", "password", "reset", "forgot", "verify", "otp", "search", "list", "all", "create",
    "new", "add", "update", "edit", "delete", "remove", "config", "settings", "status", "health", "info", "export",
    "import", "upload", "download", "file", "files", "orders", "order", "items", "item", "products", "product",
    "cart", "invoice", "invoices", "payment", "payments", "transactions", "transfer", "balance", "wallet", "roles",
    "permissions", "internal", "debug", "test", "graphql", "webhook", "callback", "impersonate", "reports")


def _clever_candidates(fed, words, cap):
    """CLEVER, context-aware enumeration (not a blind /api/ guess): brute the wordlist UNDER the prefixes/versions
    the app ACTUALLY uses (learned from the discovered paths), pivot the API version (v2 -> v1, v3), and derive the
    id + singular/plural of each observed resource. Falls back to the generic api/version shapes only when no path
    has been discovered yet. This is what turns 'spotted one API call' into 'enumerated the whole family'."""
    prefixes, versions, resources = set(), set(), []
    for p in fed:
        segs = [s for s in p.strip("/").split("/") if s]
        acc = ""
        for s in segs[:-1]:                          # the CONTAINING dirs of a discovered path = observed prefixes
            acc += "/" + s
            prefixes.add(acc + "/")
            if re.fullmatch(r"v\d+", s):
                versions.add(s)
        if segs:
            resources.append("/" + "/".join(segs))
    prefs = sorted(prefixes) if prefixes else list(_SHAPES)
    # (1) DERIVATIONS of the observed paths FIRST (highest value: version pivots, NUMERIC id-walk, singular/plural) -
    #     so a small --max-paths never truncates the very family the discovered paths point at.
    derived = []
    for r in resources:
        for v in versions:
            try:
                n = int(v[1:])
            except ValueError:
                continue
            for alt in (f"v{n + 1}", f"v{max(1, n - 1)}"):
                if alt != v:
                    derived.append(r.replace(f"/{v}/", f"/{alt}/").replace(f"/{v}", f"/{alt}"))
        rb = r.rstrip("/")
        leaf = rb.split("/")[-1]
        if leaf.isdigit():                           # NUMERIC id -> walk neighbours (BOLA/IDOR enumeration)
            parent, n = rb[: len(rb) - len(leaf)], int(leaf)
            derived += [parent + str(x) for x in {1, 2, 3, max(0, n - 1), n + 1, n + 2} if str(x) != leaf]
        else:
            derived += [rb + "/1", rb + "/2"]
            if leaf:
                derived.append(rb[: len(rb) - len(leaf)] + (leaf[:-1] if leaf.endswith("s") else leaf + "s"))
    # (2) then the wordlist nouns under EACH observed prefix (the clever brute), high-value siblings first.
    prio = list(_HIGH_VALUE) + [w for w in words if w not in _HIGH_VALUE]
    brute = []
    for w in prio:
        for pre in prefs:
            brute.append(pre + w)
        if len(brute) >= cap * 5:
            break
    return [_norm(p) for p in derived + brute]

NAME = "api-map"
KIND = "findings"
HELP = ("Method-aware API discovery: enumerate paths x {GET,POST,PUT,PATCH,DELETE,OPTIONS}, diff each vs a "
        "per-method catch-all, and report which paths exist for which verbs (write verbs first). Non-destructive.")

_WRITE = ("POST", "PUT", "PATCH", "DELETE")
_DEFAULT_METHODS = "GET,POST,PUT,PATCH,OPTIONS"     # DELETE inferred (OPTIONS/405), never sent to a real path


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Base URL, e.g. https://x or https://x/api")
    parser.add_argument("--paths", default=None, metavar="CSV|FILE",
                        help="extra candidate paths (comma-list OR a file), added to the built-in API wordlist")
    parser.add_argument("--methods", default=_DEFAULT_METHODS,
                        help=f"methods to probe (default {_DEFAULT_METHODS}); DELETE is inferred, never sent")
    parser.add_argument("--max-paths", dest="max_paths", type=int, default=400, help="cap candidate paths (400)")
    parser.add_argument("--concurrency", type=int, default=8, help="parallel path probes (8)")
    parser.add_argument("--budget", type=int, default=150, help="total wall-clock seconds (150)")
    add_header_arg(parser)
    add_common_args(parser)


def _extra_paths(spec):
    if not spec:
        return []
    if os.path.isfile(spec):
        try:
            return [ln.strip() for ln in open(spec, encoding="utf-8") if ln.strip() and not ln.startswith("#")]
        except OSError:
            return []
    return [p.strip() for p in spec.split(",") if p.strip()]


def _norm(p):
    p = (p or "").strip()
    return p if p.startswith("/") else "/" + p


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target = (args.target or "").strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    pr = urlparse(target)
    if not pr.netloc:
        output_result([], args.output, "Invalid target URL.")
        return 1
    root = f"{pr.scheme}://{pr.netloc}"
    base = pr.path.rstrip("/") if pr.path and pr.path != "/" else ""

    hdrs = {}
    for h in (getattr(args, "header", None) or []):
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()
    sess = http.session(extra_headers=hdrs)

    methods = [m.strip().upper() for m in (args.methods or "").split(",") if m.strip()]
    # fed/discovered paths FIRST (highest value); then frequency-ranked segments expanded with the common
    # api/version shapes (so nested /api/v1/<word> routes are reachable); THEN cap - so fed paths always survive.
    fed = [_norm(p) for p in _extra_paths(args.paths)]
    built = _clever_candidates(fed, _load_api_words(), max(1, args.max_paths))   # observed-prefix-driven, not blind
    paths = list(dict.fromkeys(fed + built))[: max(1, args.max_paths)]
    if not paths:
        output_result([], args.output, "No candidate paths.")
        return 1

    def make_url(tok):                                   # per-method catch-all calibration under the base path
        return f"{root}{base}/{tok}"

    baselines = {}
    for m in methods:
        try:
            baselines[m] = soft404.calibrate(make_url, m, sess, dbg)
        except Exception as exc:  # noqa: BLE001
            dbg(f"api-map: calibrate {m} failed: {exc}")
            baselines[m] = []

    deadline = time.time() + max(15, args.budget)

    def allow_of(url):
        try:
            r = http.send("OPTIONS", url, sess=sess, timeout=8, allow_redirects=False)
            a = str((r.get("headers") or {}).get("Allow") or (r.get("headers") or {}).get("allow") or "")
            return {v.strip().upper() for v in a.split(",") if v.strip()}
        except Exception:  # noqa: BLE001
            return set()

    def probe(path):
        if time.time() > deadline:
            return None
        url = f"{root}{base}{path}"
        allow = allow_of(url)
        live = {}
        tok = path.strip("/").split("/")[-1]
        for m in methods:
            if m == "OPTIONS" or time.time() > deadline:
                continue
            data = "" if m in ("POST", "PUT", "PATCH") else None   # empty body proves existence, mutates nothing
            try:
                r = http.send(m, url, sess=sess, data=data, timeout=8, allow_redirects=False)
            except Exception:  # noqa: BLE001
                continue
            st = r.get("status")
            if st is None:
                continue
            sig = soft404.fingerprint(st, r["headers"], r["body"], tok)
            ghost = soft404.is_ghost(sig, baselines.get(m, []))
            # exists for this verb: a 405 (path is real, wrong verb), advertised by Allow, or a NON-ghost non-404.
            if st == 405 or (m in allow) or (not ghost and st != 404):
                live[m] = st
        if "DELETE" in allow and "DELETE" not in live:
            live["DELETE"] = "allow"                                # inferred, never sent
        return (url, live, allow) if (live or allow) else None

    endpoints = []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        for res in ex.map(probe, paths):
            if res:
                endpoints.append(res)

    _APP = (200, 201, 202, 204, 400, 409, 422)          # app HANDLED the request (real endpoint), vs gate/not-found
    findings = []
    for url, live, allow in endpoints:
        verbs = sorted(live.keys(), key=lambda v: (v not in _WRITE, v))
        if not verbs and not allow:
            continue
        istatuses = [s for s in live.values() if isinstance(s, int)]
        allow_write = any(v in allow for v in _WRITE)
        write_app = [v for v in verbs if v in _WRITE and isinstance(live.get(v), int) and live[v] in _APP]
        method_diff = len(set(istatuses)) > 1
        get_ok = live.get("GET") in (200, 201)
        # DROP a uniform 401/403 across verbs with no advertised write verb: that is a gate/WAF, not a real,
        # method-specific endpoint (e.g. Cloudflare 403-ing /wp-config.php for every method).
        if istatuses and len(set(istatuses)) == 1 and istatuses[0] in (401, 403) and not allow_write:
            continue
        # keep only genuinely interesting endpoints: a write endpoint that the app handled, a per-verb status
        # difference (the hallmark of a real API route), an advertised write verb, or a real 200 GET.
        if not (write_app or method_diff or allow_write or get_ok):
            continue
        write = [v for v in verbs if v in _WRITE]
        allow_s = ",".join(sorted(allow))
        findings.append({
            "severity": "medium" if write else "info",
            "title": f"endpoint {url}  [{','.join(verbs) or allow_s}]",
            "url": url, "methods": verbs, "allow": allow_s,
            "info": ("live: " + ", ".join(f"{v}({live[v]})" for v in verbs))
                    + (f"; Allow: {allow_s}" if allow_s else "")
                    + ("; WRITE surface - test mass-assignment / BOLA-write / business-logic here" if write else ""),
            **repro_mod.repro(write[0] if write else (verbs[0] if verbs else "GET"), url),
        })
    findings.sort(key=lambda f: (0 if any(v in _WRITE for v in f["methods"]) else 1, f["url"]))
    dbg(f"api-map: {len(findings)} endpoints "
        f"({sum(1 for f in findings if any(v in _WRITE for v in f['methods']))} with write verbs)")
    output_result(findings, args.output)
    return 0

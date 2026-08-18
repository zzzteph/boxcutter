"""harvest - a deterministic, browser-driven DEEP crawler that maps an app's real request surface.

Where `browser-crawl` renders ONE page and grabs its XHR, `harvest` drives the whole app like a user: it
opens the target in a headless browser (CDP over system chromium, see core.cdp), dismisses consent banners,
fills and submits forms, clicks the safe controls, follows in-scope links breadth-first, and does it across
MANY states - capturing EVERY request the app makes (GET/POST/PUT/PATCH/..., XHR/fetch and full navigations,
incl. the cross-origin api.* backend) with request bodies and the Authorization the SPA sends.

It then DEDUPES into a testable corpus: ids in the path are templated (`/orders/1042` -> `/orders/{id}`), and
requests collapse by (method, path-template, param-set), so 500 captured calls become ~30 distinct endpoints.
Each corpus entry carries a copy-paste curl + raw Burp request (core.repro), and a parameter catalog records
every param seen, its inferred type (id/uuid/email/enum/text) and where it lives - so `fuzz`/`api-map`/`sqlmap`/
`graphql-audit` can consume the output directly. Optional --har writes a Burp/ZAP-importable HAR.

Safety: it never clicks logout/delete/pay/etc, never fires a raw DELETE, uses throwaway form values, stays in
scope, and is bounded by --max-pages/--max-actions/--max-time. Full-image tool: needs chromium +
websocket-client; degrades gracefully without.
"""
from __future__ import annotations

import json
import re
import time
from collections import deque
from urllib.parse import parse_qsl, urlparse

from ..core import repro as repro_mod
from ..core.args import add_common_args, add_header_arg
from ..core.cdp import CDPError, Chrome, get_session
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "harvest"
KIND = "items"
HELP = "Deep browser crawler: drive the app (click/submit/SPA), capture every request, dedupe into a corpus."

# Controls we NEVER click / forms we never submit - destructive or session-ending.
_SKIP_WORDS = ("logout", "log out", "sign out", "signout", "delete", "remove", "deactivate", "cancel account",
               "close account", "pay", "purchase", "checkout", "place order", "confirm order", "buy now",
               "send", "transfer", "withdraw", "unsubscribe", "reset", "wipe", "destroy")
# Cookie/consent banner acceptors - dismissed so the crawl proceeds instead of stalling behind a modal.
_CONSENT = ("accept all", "allow all", "accept cookies", "i agree", "agree", "got it", "ok, got it",
            "accept", "allow", "continue", "understand")

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEXID = re.compile(r"^[0-9a-f]{16,}$", re.I)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Start URL to crawl")
    parser.add_argument("--scope", dest="scope", action="append", default=[], metavar="HOST",
                        help="Extra in-scope host to crawl (repeatable). The target host is always in scope; "
                             "off-scope requests are still CAPTURED (unless filtered by --capture-host) but not "
                             "crawled.")
    parser.add_argument("--capture-host", dest="capture_hosts", action="append", default=[], metavar="HOST",
                        help="Only CAPTURE requests to these hosts (repeatable; exact or *.wildcard). Use it when "
                             "the UI is on one domain but the API is on another, e.g. --capture-host "
                             "\"*.example.com\" keeps app.example.com + api.example.com and drops third-party "
                             "trackers/CDNs. The target host and any --scope hosts are always kept. Default: "
                             "capture every host the page talks to.")
    parser.add_argument("--session", dest="session", default=None, metavar="ID",
                        help="Attach to a persistent browser session (e.g. one already logged in by "
                             "logio/prawlio) to crawl AUTHENTICATED, instead of a fresh browser.")
    parser.add_argument("--max-pages", dest="max_pages", type=int, default=40,
                        help="Max distinct states to visit (default 40).")
    parser.add_argument("--max-actions", dest="max_actions", type=int, default=20,
                        help="Max fill+click actions per state (default 20).")
    parser.add_argument("--max-time", dest="max_time", type=int, default=180,
                        help="Overall crawl budget in seconds (default 180).")
    parser.add_argument("--timeout", type=int, default=45, help="Per-page load timeout (seconds).")
    parser.add_argument("--include-assets", dest="include_assets", action="store_true",
                        help="Include static assets (images/css/fonts) in the corpus (default: skipped).")
    parser.add_argument("--har", dest="har", default=None, metavar="FILE",
                        help="Also write a HAR of every captured request (importable into Burp/ZAP).")
    add_header_arg(parser)
    add_common_args(parser)


# -- url / param helpers -----------------------------------------------------
def _template(url: str) -> str:
    """Collapse id-like path segments so `/orders/1042` and `/orders/1043` become one `/orders/{id}` endpoint."""
    p = urlparse(url)
    out = []
    for s in p.path.split("/"):
        if not s:
            out.append(s)
        elif s.isdigit():
            out.append("{id}")
        elif _UUID.match(s):
            out.append("{uuid}")
        elif _HEXID.match(s):
            out.append("{hex}")
        elif len(s) >= 24 and re.search(r"\d", s):
            out.append("{id}")
        else:
            out.append(s)
    return f"{p.scheme}://{p.netloc}{'/'.join(out)}"


def _val_type(v: str) -> str:
    if v is None or v == "":
        return "empty"
    if _UUID.match(v):
        return "uuid"
    if v.isdigit():
        return "int"
    if _EMAIL.match(v):
        return "email"
    if _HEXID.match(v):
        return "hex"
    if v.lower() in ("true", "false"):
        return "bool"
    return "text"


def _host_ok(host: str, patterns: list) -> bool:
    """Whether a request host passes the capture filter. Empty patterns => capture everything (default). A
    `*.example.com` pattern matches the apex AND any subdomain."""
    if not patterns:
        return True
    host = (host or "").lower()
    for p in patterns:
        p = (p or "").lower().strip()
        if p.startswith("*."):
            base = p[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == p:
            return True
    return False


def _param_pairs(url: str, body: str | None, mime: str) -> list[tuple]:
    """(where, name, value) for every query + body param, best-effort (urlencoded or JSON body)."""
    pairs = [("query", k, v) for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True)]
    b = (body or "").strip()
    if b:
        if "json" in (mime or "") or b[:1] in "{[":
            try:
                obj = json.loads(b)
                if isinstance(obj, dict):
                    pairs += [("body", k, str(v)) for k, v in obj.items()]
            except (ValueError, TypeError):
                pass
        else:
            pairs += [("body", k, v) for k, v in parse_qsl(b, keep_blank_values=True)]
    return pairs


# -- interaction (deterministic, bounded) ------------------------------------
def _dismiss_consent(page, dbg) -> None:
    for t in _CONSENT:
        try:
            if page.find_text(t):
                page.click(f"text={t}")
                page.wait(200)
                dbg(f"harvest: dismissed a consent/overlay via {t!r}")
                return
        except CDPError:
            pass


def _auto_fill(page, budget, dbg) -> int:
    """Type a throwaway value into empty text-like inputs and press Enter - reaches the 'enter your address'
    style APIs a click alone never triggers."""
    filled = 0
    for _ in range(min(6, budget)):
        try:
            val = page.fill_nth(0)
        except CDPError:
            break
        if not val:
            break
        filled += 1
        try:
            page.press("enter")
        except CDPError:
            pass
        page.wait(350)
    return filled


def _auto_click(page, budget, dbg) -> int:
    """Click through live clickable elements up to the budget, peeking each label first so a destructive
    control (logout/delete/pay/...) is skipped WITHOUT ever being clicked."""
    clicked = 0
    while clicked < budget:
        try:
            if page.clickable(1) < 1:
                break
            label = (page.peek_nth(0) or "").lower()
            if label and any(w in label for w in _SKIP_WORDS):
                page.mark_done(0)
                continue
            page.click_nth(0)
        except CDPError:
            break
        clicked += 1
        page.wait(300)
    return clicked


def _in_scope(url: str, scope: set) -> bool:
    return (urlparse(url).hostname or "") in scope


def _crawl(page, target, opts, dbg, navigate=True) -> None:
    """Breadth-first over in-scope document URLs; each state is interacted with. Requests accumulate in the CDP
    session across every state, so the corpus is harvested from the whole run afterwards."""
    scope = {h for h in opts["scope"]}
    scope.add(urlparse(target).hostname or "")
    if navigate:
        page.navigate(target, wait="networkidle")
    scope.add(urlparse(page.current_url()).hostname or "")

    frontier = deque([target])
    queued = {_template(target)}
    visited = 0
    start = time.monotonic()

    while frontier and visited < opts["max_pages"] and (time.monotonic() - start) < opts["max_time"]:
        url = frontier.popleft()
        try:
            if page.current_url().split("#")[0] != url.split("#")[0]:
                page.navigate(url, wait="networkidle")
        except CDPError as exc:
            dbg(f"harvest: navigate failed {url}: {exc}")
            continue
        visited += 1
        dbg(f"harvest: [{visited}/{opts['max_pages']}] {url}")
        _dismiss_consent(page, dbg)
        _auto_fill(page, opts["max_actions"], dbg)
        _auto_click(page, opts["max_actions"], dbg)
        try:
            page.scroll("bottom")
            page.wait(300)
        except CDPError:
            pass
        # enqueue new in-scope, not-yet-templated links
        for h in {x for x in scope if x}:
            try:
                found = page.links(same_host=h)
            except CDPError:
                found = []
            for link in found:
                tmpl = _template(link)
                if tmpl not in queued and _in_scope(link, scope):
                    queued.add(tmpl)
                    frontier.append(link)
    dbg(f"harvest: crawled {visited} state(s), frontier left {len(frontier)}")


# -- corpus + outputs --------------------------------------------------------
def _build(page, opts) -> tuple[list, dict, dict]:
    """From the session's full request log + XHR/fetch flows, build the deduped endpoint corpus and the
    parameter catalog. Returns (items, param_catalog, stats)."""
    reqs = page.requests(include_all=opts["include_assets"])
    patterns = opts.get("capture_hosts") or []
    if patterns:
        reqs = [r for r in reqs if _host_ok(urlparse(r["url"]).hostname or "", patterns)]
    flows = {(f["method"], f["url"]): f for f in page.flows()}

    corpus: dict = {}
    catalog: dict = {}
    for r in reqs:
        m, u = r["method"], r["url"]
        fl = flows.get((m, u), {})
        body = fl.get("req_body")
        mime = fl.get("mime", "")
        auth = fl.get("req_auth")
        tmpl = _template(u)
        pairs = _param_pairs(u, body, mime)
        pnames = sorted(f"{w}:{n}" for w, n, _ in pairs)
        key = (m, tmpl, tuple(pnames))
        agg = corpus.get(key)
        if agg is None:
            agg = {"method": m, "url": u, "template": tmpl, "type": r.get("type", "other"),
                   "status": r.get("status"), "params": [n for _, n, _ in pairs], "count": 0,
                   "_body": body, "_auth": auth, "_mime": mime}
            corpus[key] = agg
        agg["count"] += 1
        # parameter catalog: name -> {types, where, sample, count}
        for where, name, value in pairs:
            c = catalog.setdefault(name, {"types": set(), "where": set(), "sample": value, "count": 0})
            c["types"].add(_val_type(value))
            c["where"].add(where)
            c["count"] += 1

    items = []
    for agg in sorted(corpus.values(), key=lambda a: (a["template"], a["method"])):
        headers = {}
        if agg["_auth"]:
            headers["Authorization"] = agg["_auth"]
        if agg["_body"] and ("json" in (agg["_mime"] or "") or agg["_body"].strip()[:1] in "{["):
            headers.setdefault("Content-Type", "application/json")
        item = {"method": agg["method"], "url": agg["url"], "template": agg["template"],
                "type": agg["type"], "status": agg["status"], "params": agg["params"],
                "seen": agg["count"]}
        item.update(repro_mod.repro(agg["method"], agg["url"], headers or None, agg["_body"]))
        items.append(item)

    param_catalog = {n: {"types": sorted(c["types"]), "where": sorted(c["where"]),
                         "sample": c["sample"], "count": c["count"]} for n, c in sorted(catalog.items())}
    stats = {"requests_captured": len(reqs), "endpoints": len(items), "params": len(param_catalog),
             "methods": sorted({i["method"] for i in items})}
    return items, param_catalog, stats


def _write_har(page, path: str, patterns=None) -> None:
    reqs = page.requests(include_all=True)
    if patterns:
        reqs = [r for r in reqs if _host_ok(urlparse(r["url"]).hostname or "", patterns)]
    flows = {(f["method"], f["url"]): f for f in page.flows()}
    entries = []
    for r in reqs:
        f = flows.get((r["method"], r["url"]), {})
        req = {"method": r["method"], "url": r["url"], "httpVersion": "HTTP/1.1",
               "headers": ([{"name": "Authorization", "value": f["req_auth"]}] if f.get("req_auth") else []),
               "queryString": [{"name": k, "value": v} for k, v in parse_qsl(urlparse(r["url"]).query)],
               "cookies": [], "headersSize": -1, "bodySize": len(f.get("req_body") or "")}
        if f.get("req_body"):
            req["postData"] = {"mimeType": f.get("mime", "application/octet-stream"), "text": f["req_body"]}
        entries.append({
            "startedDateTime": "1970-01-01T00:00:00.000Z", "time": 0, "request": req,
            "response": {"status": r.get("status") or 0, "statusText": "", "httpVersion": "HTTP/1.1",
                         "headers": [], "cookies": [], "redirectURL": "",
                         "content": {"size": r.get("size", 0), "mimeType": f.get("mime", ""),
                                     "text": f.get("resp_body") or ""},
                         "headersSize": -1, "bodySize": r.get("size", 0)},
            "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}})
    doc = {"log": {"version": "1.2", "creator": {"name": "boxcutter-harvest", "version": "1"},
                   "entries": entries}}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)


def run(args) -> int:
    target = args.target.strip()
    dbg = debug_logger(args.debug)
    if not is_valid_url(target):
        output_result([], args.output, "Invalid URL.")
        return 1

    headers = {}
    for raw in args.header or []:
        if ":" in raw:
            k, v = raw.split(":", 1)
            headers[k.strip()] = v.strip()

    scope = [h.strip().lower() for h in (args.scope or []) if h.strip()]
    cap = [h.strip().lower() for h in (args.capture_hosts or []) if h.strip()]
    if cap:                                   # always keep the UI host + crawl scope alongside the given hosts
        cap = list(dict.fromkeys(cap + [(urlparse(target).hostname or "").lower()] + scope))
    opts = {"scope": scope, "max_pages": args.max_pages, "max_actions": args.max_actions,
            "max_time": args.max_time, "include_assets": args.include_assets, "capture_hosts": cap}

    sid = (getattr(args, "session", None) or "").strip()
    try:
        if sid:
            page, fresh = get_session(sid, headers=headers, timeout=args.timeout, debug=dbg)
            _crawl(page, target, opts, dbg, navigate=fresh)
            items, catalog, stats = _build(page, opts)
            if args.har:
                _write_har(page, args.har, opts["capture_hosts"])
        else:
            with Chrome(headers=headers, timeout=args.timeout, debug=dbg) as page:
                _crawl(page, target, opts, dbg, navigate=True)
                items, catalog, stats = _build(page, opts)
                if args.har:
                    _write_har(page, args.har, opts["capture_hosts"])
    except CDPError as exc:
        output_result([], args.output, f"harvest unavailable: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        output_result([], args.output, f"harvest failed: {exc}")
        return 1

    dbg(f"harvest: {stats['requests_captured']} request(s) -> {stats['endpoints']} endpoint(s), "
        f"{stats['params']} param(s); methods {','.join(stats['methods'])}")
    if args.har:
        dbg(f"harvest: HAR written to {args.har}")
    output_result(items, args.output, extra={"stats": stats, "param_catalog": catalog,
                                              "har": args.har or None})
    return 0

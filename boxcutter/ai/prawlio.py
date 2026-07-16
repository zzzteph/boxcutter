"""prawlio - AUTHENTICATED crawl: log in with logio, then crawl the app the way a USER would - by clicking.

Chains the standalone login agent (logio) with an agentic VISUAL crawler so you get the POST-AUTHENTICATION
API surface. logio discovers + verifies the login (its fresh-browser replay model); prawlio then REPLAYS that
verified login into a PERSISTENT browser session and runs an LLM crawler that drives visual-driver EXACTLY like
the login agent - reading each gridded screenshot and click/move/put-ing through the interface, opening every
area and FILLING & SUBMITTING forms. It does NOT parse the DOM for links; it INTERACTS with the app in the
browser and captures the API requests those real interactions fire. Everything runs in ONE process, so the
persistent session logio logs in survives for the crawler to keep driving.

  boxcutter prawlio https://app.example.com --context "creds are user:pass" \
    --provider litellm --model "openai/gpt-5.1" --api-key ... --base-url https://gateway.example.com

Output: the list of API requests actually made while crawling the authenticated app (feeds the fuzzers).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

from ..core import agentlog
from ..core.envelope import debug_logger, debug_print, harvest_images, output_result, write_report
from ..irvin import briefing
from ..irvin.provider import PROVIDERS, add_agent_args
from ..tools import toolschema

NAME = "prawlio"
KIND = "items"
HELP = "Authenticated crawl: log in with logio, then crawl the app under that session and list the URLs found."

_SESSION = "prawlio"        # the persistent browser session logio's flow logs in and the crawler attaches to

_CRAWLER_SYSTEM = (
    "You are PRAWL, an AUTHENTICATED web CRAWLER. You are ALREADY LOGGED IN as a real user - the browser has a "
    "live session. GOAL: exercise as much of the app as you can - open every page, click every link/menu, and "
    "FILL & SUBMIT forms - so the app fires as many distinct API REQUESTS as possible. Those captured requests "
    "are the whole deliverable. This is a STAGING environment, so acting on it (submitting forms, saving "
    "changes, adding items) is EXPECTED and fine.\n"

    "TOOL - visual-driver, driven EXACTLY like the login agent did: its browser session PERSISTS across your "
    "calls - it CONTINUES where you left off, it does NOT reset. Each call returns a SCREENSHOT with a "
    "coordinate GRID (x across the top, y down the left). READ the screenshot, identify the element, read its "
    "x,y off the grid, and act by coordinate. Chain a few actions with a `screen` between them; you get one "
    "screenshot per `screen`, in order.\n"

    "ACTIONS - use ONLY these: screen | wait:SECONDS | move:X,Y | click:X,Y | put:TEXT (type into the FOCUSED "
    "field) | scroll:down|up | probe:X,Y (what's at x,y) | click_text:TEXT (click a control by its visible "
    "text) | goto:URL (navigate to a route) | requests:api (dump the API calls captured so far). Coordinates "
    "take a comma or colon.\n"

    "HOW TO CRAWL - poke at EVERYTHING like a real user:\n"
    "  - Open every AREA: account, profile, order history, addresses, payment methods, settings, favourites, "
    "notifications, help, menus, tabs, filters. `screen` after each to see it, then move to the NEXT area.\n"
    "  - FILL & SUBMIT forms - this triggers the most API calls: click a field, `put:` a plausible value, fill "
    "the rest, then click the submit/save button. Search boxes, filters, address forms, profile edits, 'add' "
    "dialogs - submit them. Read each field's x,y off the grid, click it, THEN put.\n"
    "  - SAMPLE dynamically-generated similar content - do NOT click every item. When the page shows a "
    "LIST/FEED of items rendered from the SAME template (blog posts, products, search results, order rows, "
    "notification cards, comments), every item hits the SAME functionality/endpoint - so open just 2-3 "
    "REPRESENTATIVE ones to exercise the detail view, then MOVE ON to a DIFFERENT section. The 40th blog post "
    "teaches us nothing new; a section you haven't opened does. Spend effort on DISTINCT functionalities, not "
    "the same one repeated over different data.\n"
    "  - `scroll` to load lazy content, open detail pages, and use `goto:URL` to jump to routes you noticed.\n"
    "  - Run `requests:api` now and then to see what's captured and steer toward areas you haven't hit yet.\n"

    "REACHING DEEP FUNCTIONALITIES - use the SAME discipline the login agent used: some pages/links are NOT one "
    "click away, they need a multi-step FLOW (open a menu -> wait -> screen -> click a submenu -> wait -> screen "
    "-> click the item). Build the path STEP BY STEP: act, `wait` for it to load (pages load slowly - `wait:5`-"
    "`wait:10`), `screen` to VERIFY the change, then the next step. Read each target's x,y off the grid; if "
    "you're unsure what is at a spot, `probe:X,Y` FIRST. Your session PERSISTS, so keep going DEEPER - never "
    "restart from the top. If a click does NOTHING (the newest screenshot shows no change), your aim MISSED - "
    "re-read the coordinate off the grid (or probe around it to find the control), and retry that ONE step; do "
    "NOT abandon the flow. Always judge from the NEWEST screenshot, never an older one.\n"

    "ONE limit, practical (NOT safety - staging is fine to act on): do NOT LOG OUT and do NOT delete/close the "
    "account - those END your session and kill the crawl. Everything else is fair game.\n"

    "HOW FAR TO GO: KEEP CRAWLING until you have genuinely run out of NEW interface to explore, or you have "
    "exercised the target number of distinct functionalities (I tell you the running count after each call). Do "
    "NOT stop while unvisited areas remain - always move to a section you have not opened yet. When you TRULY "
    "finish, reply with a SHORT text summary (and NO tool call) of what you visited and submitted.\n"

    + agentlog.NARRATE)

_MORE = (
    "You stopped, but you've only reached {n} of the {target} distinct functionalities we want, and there are "
    "almost certainly areas you haven't opened yet - other menu items, tabs, account sub-pages, filters, "
    "forms. Keep crawling: open a NEW area you have NOT visited and interact with it (click, scroll, fill & "
    "submit). Only stop when you have GENUINELY run out of new interface.")

_REAUTH = (
    "Your session had dropped to a login / identity-provider page, so I automatically LOGGED YOU BACK IN. Take "
    "a `screen` to see where you are now and CONTINUE crawling the app's functionality - do not try to work the "
    "login page yourself.")

# A URL that looks like a login / identity-provider page: an auth-ish path, or a host that looks like an IdP
# (access./login./auth./id./accounts./sso.). Used to notice the session dropped so we can log back in.
_LOGIN_URL_RE = re.compile(
    r"(?i)(/(auth|login|sign[-_]?in|signin|logon|oauth2?|openid|sso|authorize|authenticate|session/new)(/|$|\?|#))"
    r"|(^https?://(?:[^/]*\.)?(access|login|auth|id|idp|accounts?|sso|signin|secure)\.)")


def _crawler_tool_spec() -> dict:
    """visual-driver restricted to the crawl action set: navigation + form filling/submitting + capture."""
    spec = toolschema.build("visual-driver")
    schema = json.loads(json.dumps(spec["schema"]))
    schema["properties"] = {k: v for k, v in schema["properties"].items() if k in ("target", "action")}
    schema["required"] = [r for r in schema.get("required", []) if r in schema["properties"]]
    if "action" in schema["properties"]:
        schema["properties"]["action"]["description"] = (
            "A crawl action; repeatable, run in order. Use ONLY: screen | wait:SECONDS | move:X,Y | click:X,Y | "
            "put:TEXT (type into the focused field) | scroll:down|up | probe:X,Y | click_text:TEXT | goto:URL | "
            "requests:api. Coordinates take a comma or colon.")
    return {"name": "visual-driver",
            "description": "Drive the logged-in browser by screen coordinates; returns a gridded screenshot.",
            "schema": schema}


def _crawl_rewrite(args: dict, sid: str, grid, trace) -> dict:
    """Pin the persistent (authenticated) session + grid/trace onto a crawl call. No token substitution: the
    crawler navigates and reads, it never types credentials."""
    a = dict(args or {})
    a["session"] = sid
    if grid is not None:
        a["grid"] = grid
    if trace:
        a["trace"] = trace
    return a


def _flows_of(raw: str) -> list:
    """The API (XHR/fetch) request records a visual-driver reply carries - every call returns the requests its
    actions triggered, so we harvest them straight out of each crawl call (method + url, plus status/body when
    the driver reports them, so the fuzzers get real injectable requests, not bare URLs)."""
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return []
    data = env.get("data") if isinstance(env, dict) else None
    out = []
    if isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict) and rec.get("type") != "state":
                url, method = rec.get("url"), rec.get("method")
                if url and method:
                    item = {"method": method, "url": url, "type": "xhr"}
                    for k in ("status", "req_body", "mime"):
                        if rec.get(k) not in (None, ""):
                            item[k] = rec[k]
                    out.append(item)
    return out


_IDLIKE = re.compile(r"(?i)^(?:\d+|[0-9a-f]{8,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")


def _norm_path(path: str) -> str:
    """Collapse id-like path segments to {id} so DYNAMICALLY-GENERATED detail pages of the same kind
    (/posts/1, /posts/2, /posts/3 ...) count as ONE functionality, not fifty - a feed of blog posts is one
    feature. Numeric ids, long hex, and UUIDs are treated as ids."""
    segs = ["{id}" if _IDLIKE.match(s) else s for s in path.strip("/").split("/") if s]
    return ("/" + "/".join(segs)).lower()


def _visited_of(raw: str) -> set:
    """The distinct UI FUNCTIONALITIES a visual-driver reply touched - the PAGE(s) it landed on (id-like
    segments collapsed to {id} so dynamically-generated detail pages don't each count) plus the visible NAME of
    every link/button it clicked. This (not raw API endpoints) is what 'how many functionalities have I
    covered' should count: the interface the agent actually exercised, by name and page."""
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return set()
    data = env.get("data") if isinstance(env, dict) else None
    visited: set = set()
    if not isinstance(data, list):
        return visited
    for rec in data:
        if not isinstance(rec, dict) or rec.get("type") != "state":
            continue
        path = _norm_path(urlparse(rec.get("url") or "").path)
        if path and path != "/":
            visited.add("page:" + path)                     # a functionality PAGE the crawl reached ({id}-collapsed)
        for r in rec.get("results") or []:
            if not isinstance(r, dict):
                continue
            if str(r.get("action", "")).split(":", 1)[0].strip().lower() not in \
                    ("click", "dblclick", "click_text", "tap"):
                continue
            clicked = r.get("clicked") if isinstance(r.get("clicked"), dict) else {}
            label = clicked.get("text") or ""
            if not label and isinstance(r.get("hit"), str):
                m = re.search(r'"([^"]+)"', r["hit"])        # the visible text inside `button "Order History"`
                label = m.group(1) if m else r["hit"]
            label = (label or "").strip().lower()
            if label:
                visited.add("click:" + label)               # a link/button NAME the crawl clicked
    return visited


def _current_url(raw: str) -> str:
    """The URL the browser is on after a visual-driver reply (from its state record)."""
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return ""
    data = env.get("data") if isinstance(env, dict) else None
    if isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict) and rec.get("type") == "state":
                return rec.get("url") or ""
    return ""


def _deauthed(url: str, base_host: str) -> bool:
    """True when the crawl has landed on a login / identity-provider page - i.e. the session dropped and we
    need to log back in. Heuristic: an auth-ish URL on a DIFFERENT host than the app (the usual SSO case, e.g.
    an app host redirected to a separate SSO / identity-provider host), so the app's own pages are never
    mistaken for a login drop."""
    if not url:
        return False
    host = (urlparse(url).hostname or "").lower()
    same = bool(host and base_host and (host == base_host or host.endswith("." + base_host)
                                        or base_host.endswith("." + host)))
    return not same and bool(_LOGIN_URL_RE.search(url))


def _reauth(base_url: str, sid: str, headers: list, grid, trace, login_flow: list, subs: dict,
            debug: bool = False) -> str:
    """Log back in inside the PERSISTENT crawl session: navigate back to the app, then replay the verified
    login flow (creds substituted). Returns the resulting reply's URL so the caller can confirm we're back."""
    argv = ["visual-driver", base_url, "--session", sid, "--grid", str(grid)]
    if trace:
        argv += ["--trace", trace]
    argv += ["--action", "goto:" + base_url]              # return to the app before replaying the login
    for a in login_flow:
        argv += ["--action", _sub(a, subs)]
    _env, raw = _call(argv, headers, debug)
    return _current_url(raw)


def _explore(base_url: str, base_host: str, provider, sid: str, headers: list, grid, trace,
             stop_after: int, hard_cap: int, login_flow: list, subs: dict, debug: bool = False,
             deadline: float | None = None) -> list:
    """Agentic visual crawl: an LLM drives the already-authenticated browser (click/move/put via visual-driver,
    exactly like the login agent) to exercise the app's functionality, and we harvest every API request its
    interactions fire. Runs until the agent runs OUT of new interface, or `stop_after` distinct UI
    functionalities have been exercised, bounded by `hard_cap` agent steps. If the session DROPS to a login
    page mid-crawl (e.g. an SSO timeout), it recalls the login flow to get back in rather than stalling on the
    auth wall. Returns all the collected request items."""
    dbg = debug_logger(debug)                   # verbose tier: full reasoning + per-call outcome, only under --debug
    tools_spec = [_crawler_tool_spec()]
    messages = [{"role": "user", "content":
                 f"You are logged in to {base_url}. Crawl its functionality to trigger as many API requests as "
                 "possible. Start with a `screen` to see where you are, then open the account/menu and work "
                 "through the sections one by one - clicking links and FILLING & SUBMITTING forms as you go "
                 "(staging, so submitting is fine). Just don't log out or delete the account."}]
    found: list = []
    visited: set = set()        # distinct UI functionalities (pages landed on + link/button NAMES clicked)
    last_url = ""
    reauths, max_reauth = 0, 3
    for step in range(max(1, hard_cap)):
        last_step = step >= hard_cap - 1
        if deadline and time.time() > deadline:
            debug_print(f"prawlio[crawl]> wall-clock budget reached at step {step} - finalizing the crawl")
            break
        # if the crawl dropped to a login/identity page, the session expired or we got logged out - recall the
        # login flow to get back in, rather than nudging the agent to push through an auth wall it can't pass.
        if login_flow and reauths < max_reauth and _deauthed(last_url, base_host):
            reauths += 1
            debug_print(f"prawlio[crawl]> session dropped to login ({last_url!r}) - re-authenticating "
                        f"({reauths}/{max_reauth}) ...")
            last_url = _reauth(base_url, sid, headers, grid, trace, login_flow, subs, debug)
            messages.append({"role": "user", "content": _REAUTH})
            continue
        try:
            resp = provider.send(_CRAWLER_SYSTEM, messages, tools_spec)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"prawlio: crawl provider error: {exc}\n")
            break
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        if text.strip():
            flat = " ".join(text.split())
            if debug:
                dbg("prawlio[crawl]: " + flat)                   # the WHY, in full, under --debug
            else:
                debug_print("prawlio[crawl]> " + flat[:200])
        if not calls:
            # the agent thinks it's out of new interface. Respect that UNLESS it's stopping well short of the
            # target with budget left - then push it to open an area it hasn't visited.
            if len(visited) < stop_after and not last_step:
                debug_print(f"prawlio[crawl]> agent stopped at {len(visited)}/{stop_after} functionalities - nudging on")
                messages.append({"role": "user", "content": _MORE.format(n=len(visited), target=stop_after)})
                continue
            break
        results = []
        for c in calls:
            if c["name"] != "visual-driver":
                results.append({"id": c["id"], "output": json.dumps({"error": "only visual-driver is available"}),
                                "images": []})
                continue
            argv = toolschema.to_argv("visual-driver", _crawl_rewrite(c["args"], sid, grid, trace))
            debug_print("prawlio[crawl]> boxcutter " + " ".join(str(a) for a in toolschema.to_argv("visual-driver", c["args"])))
            _env, raw = _call(argv, headers, debug)
            dbg(f"    <- visual-driver: {agentlog.summarize(raw)}")
            found += _flows_of(raw)             # the API requests (the deliverable)
            visited |= _visited_of(raw)         # the UI functionalities (the coverage / how-far metric)
            u = _current_url(raw)
            if u:
                last_url = u                    # watched so a drop to a login page triggers re-auth next turn
            clean, images = harvest_images(raw, max_images=6)
            results.append({"id": c["id"], "output": clean, "images": images})
        # steer toward NEW areas: report how many distinct UI functionalities are covered vs the target (folded
        # into the tool result so we don't stack two consecutive user turns)
        if results:
            results[-1]["output"] += (
                f"\n\n[COVERAGE] {len(visited)} distinct functionalities visited so far (pages opened + links "
                f"you clicked; target {stop_after}). Open a NEW section or click a link/button you have NOT "
                "used yet; stop only when there is no new interface left or the target is reached.")
        messages += provider.tool_results(results)
        if len(visited) >= stop_after:
            debug_print(f"prawlio[crawl]> reached {len(visited)} distinct functionalities "
                        f"(>= {stop_after}) - stopping")
            break
    return found


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL (the app root)")
    parser.add_argument("--creds", default=None, metavar="USER:PASS", help="Credentials to log in with")
    parser.add_argument("--grid", type=int, default=25, metavar="PX", help="Coordinate-grid spacing for login")
    parser.add_argument("--trace", default="trace", metavar="DIR",
                        help="Trace dir (see logio); default ./trace, in Docker pass --trace /trace; '' to disable")
    parser.add_argument("--stop-after", dest="stop_after", type=int, default=50,
                        help="Stop the crawl once this many DISTINCT UI functionalities (pages opened + "
                             "link/button names clicked) have been visited; it also stops early if the agent "
                             "runs out of new interface")
    parser.add_argument("--crawl-steps", dest="crawl_steps", type=int, default=60,
                        help="Hard safety cap on visual-crawl agent steps (the stop-after / no-more-interface "
                             "conditions normally end it first)")
    add_agent_args(parser, max_steps=14, budget=1800)


def _call(argv: list, headers: list, debug: bool = False) -> tuple:
    """Run a boxcutter sub-command IN-PROCESS (so the persistent session registry is shared) and return
    (envelope_dict, raw_stdout). stderr is left ALONE so the sub-tool's live progress still streams to the
    console; only stdout (the JSON envelope) is captured. Under --debug the sub-tool also gets --debug so its
    own diagnostics (visual-driver's ok/failed/flow counts) stream too."""
    from ..cli import main as cli_main
    flag = toolschema.build(argv[0])["flag_of"].get("header") if argv else None
    if flag and headers:
        argv = argv + [x for h in headers for x in (flag, h)]
    argv = agentlog.forward_debug(argv, debug)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            cli_main(list(argv))
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": f"{argv[0]} failed: {exc}"}, ""
    raw = buf.getvalue().strip()
    try:
        return json.loads(raw), raw
    except Exception:  # noqa: BLE001
        return {}, raw


def _sub(action: str, subs: dict) -> str:
    for tok, val in subs.items():
        action = action.replace(tok, val)
    return action


def crawl(provider, base_url: str, subs: dict, grid=25, trace=None, stop_after: int = 50,
          crawl_steps: int = 60, headers=None, login_max_steps: int = 14, debug: bool = False) -> dict:
    """The reusable AUTHENTICATED-CRAWL CORE: log in (via logio.login), replay the login into a persistent
    browser session, then run the visual crawl - returns {authenticated, requests}. Shared by the prawlio CLI
    and IRVIN's `explore` executor, so both use the same login+crawl without duplication. Caller owns session
    teardown (close_all_sessions)."""
    headers = list(headers or [])
    base_host = (urlparse(base_url).hostname or "").lower()
    from .logio import login as logio_login
    res = logio_login(provider, base_url, subs, grid=grid, trace=trace, headers=headers,
                      max_steps=login_max_steps, debug=debug)
    if not res.get("authenticated") or not res.get("flow"):
        return {"authenticated": False, "requests": []}
    login_flow = res["flow"]
    vd_argv = ["visual-driver", base_url, "--session", _SESSION, "--grid", str(grid)]
    if trace:
        vd_argv += ["--trace", trace]
    for a in login_flow:
        vd_argv += ["--action", _sub(a, subs)]
    _call(vd_argv, headers, debug)                        # replay the login into the persistent crawl session
    items = _explore(base_url, base_host, provider, _SESSION, headers, grid, trace,
                     stop_after, crawl_steps, login_flow, subs, debug)
    seen: set = set()
    reqs: list = []
    for it in items:
        if isinstance(it, dict) and it.get("url"):
            key = (it.get("method", "GET"), it["url"])
            if key not in seen:
                seen.add(key)
                reqs.append(it)
    return {"authenticated": True, "requests": reqs}


def run(args) -> int:
    target = args.target.strip()
    if not target:
        output_result([], args.output, "a target is required")
        return 2
    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"prawlio: provide --api-key or set {provider_cls.env} for --provider {args.provider}\n")
        return 2

    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    base_host = (urlparse(base_url).hostname or "").lower()
    headers = list(args.header or [])
    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)

    # resolve credentials (needed to substitute the login flow's __USER__/__PASS__ tokens when we replay it)
    creds = args.creds
    if (not creds or ":" not in creds) and args.context.strip():
        cfg = briefing.parse(provider, args.context, base_host)
        headers += cfg.get("headers", [])
        cc = cfg.get("creds") or []
        if cc:
            creds = f"{cc[0]['user']}:{cc[0]['password']}"
            sys.stderr.write("prawlio :: credentials parsed from --context (values hidden)\n")
    if not creds or ":" not in creds:
        output_result([], args.output, "prawlio needs credentials - pass --creds \"user:pass\" or --context")
        return 2
    user, _, pw = creds.partition(":")
    subs = {"__USER__": user, "__PASS__": pw, "__CREDS__": f"{user}:{pw}"}

    grid = args.grid
    trace = args.trace
    items: list = []
    authenticated = False
    login_flow: list = []
    try:
        # 1) LOG IN with logio (its own fresh-browser agent) - we only need the verified login flow back.
        debug_print("prawlio :: [1/3] logging in with logio ...")
        logio_argv = ["logio", target, "--provider", args.provider, "--grid", str(grid),
                      "--max-steps", str(args.max_steps)]
        if args.model:
            logio_argv += ["--model", args.model]
        if key:
            logio_argv += ["--api-key", key]
        if args.base_url:
            logio_argv += ["--llm-proxy-url", args.base_url]
        if args.creds:
            logio_argv += ["--creds", args.creds]
        if args.context:
            logio_argv += ["--context", args.context]
        if trace:
            logio_argv += ["--trace", trace]
        env, _raw = _call(logio_argv, headers, args.debug)
        rec = (env.get("data") or [{}])[0] if isinstance(env, dict) else {}
        authenticated = bool(rec.get("authenticated"))
        login_flow = rec.get("flow") or []
        if not authenticated or not login_flow:
            debug_print("prawlio :: login did NOT succeed - cannot crawl authenticated; stopping.")
            output_result([], args.output,
                          "prawlio: logio did not authenticate (no usable login flow); nothing to crawl")
            return 1

        # 2) REPLAY that login into a PERSISTENT session so we hold a live, authenticated browser to crawl.
        debug_print(f"prawlio :: [2/3] replaying the {len(login_flow)}-step login into a persistent session ...")
        vd_argv = ["visual-driver", target, "--session", _SESSION, "--grid", str(grid)]
        if trace:
            vd_argv += ["--trace", trace]
        for a in login_flow:
            vd_argv += ["--action", _sub(a, subs)]
        _call(vd_argv, headers, args.debug)

        # 3) CRAWL by INTERACTING with the UI like a user - the LLM reads each screenshot and click/move/put's
        # via visual-driver EXACTLY like the login agent. We do NOT parse the DOM for links; we collect the API
        # requests those real browser interactions actually fire.
        debug_print(f"prawlio :: [3/3] visual crawl - clicking/typing through the UI until ~{args.stop_after} "
                    "functionalities or no interface left ...")
        items = _explore(base_url, base_host, provider, _SESSION, headers, grid, trace,
                         args.stop_after, args.crawl_steps, login_flow, subs, args.debug,
                         deadline=time.time() + max(30, args.budget))
    finally:
        from ..core.cdp import close_all_sessions
        close_all_sessions()

    # dump ALL requests captured during the visual crawl, deduped by (method, url) so GET /x and POST /x both
    # survive as distinct requests (the fuzzers care about the method).
    seen: set = set()
    reqs: list = []
    for it in items:
        if not isinstance(it, dict):
            continue
        url, method = it.get("url"), it.get("method", "GET")
        key = (method, url)
        if url and key not in seen:
            seen.add(key)
            reqs.append(it)
    debug_print(f"\nprawlio :: authenticated={authenticated} :: {len(reqs)} distinct request(s) captured "
                f"during the visual crawl of {base_url}")
    for it in reqs[:60]:
        debug_print(f"  {it.get('method', 'GET'):6} {it.get('url', '')}")
    if len(reqs) > 60:
        debug_print(f"  ... and {len(reqs) - 60} more")

    report = "\n".join([f"## Prawlio - authenticated crawl: {base_url}", "",
                        f"**Authenticated:** {authenticated}",
                        f"**Distinct requests captured:** {len(reqs)}", ""]
                       + [f"- {it.get('method', 'GET')} {it.get('url', '')}" for it in reqs])
    write_report(getattr(args, "report", None), report)
    output_result(reqs, args.output)
    return 0

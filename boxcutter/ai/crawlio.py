"""crawlio - a focused, single-agent CRAWLER whose ONE job is a comprehensive, VERIFIED endpoint list.

It drives the mapping tools (screenshot, katana-crawl, browser-crawl, js-endpoints, swagger-specs/-endpoints,
path-bust, http-request) in one LLM tool-calling loop, then a DETERMINISTIC code gate re-verifies the
result. The whole value is the last mile most crawlers skip - a host that returns the same page for any path
(a catch-all / soft-404 / SPA front-controller) makes every guessed path look "alive". crawlio's model is told
to fingerprint that; crawlio's CODE then re-checks it, so the guarantee doesn't depend on the model behaving.

Guarantees enforced in code (not just the prompt):
  - GHOST GATE: after the crawl, every endpoint is re-tested against the host's catch-all fingerprint (bare +
    query-control) and DROPPED if it's just the front-controller. A 200 is never trusted as proof.
  - SCOPE: dispatch is refused for any URL outside the target's host / given path-subtree; the output is scoped too.
  - DEDUP: endpoints are collapsed to (method, path-family) in code - /user/1 and /user/2 are one.
  - TRUSTED-ONLY FALLBACK: if the agent never finalizes, we emit only URLs from tools that OBSERVE real
    behaviour or SELF-VERIFY (path-bust gates its own output) - never an unverified brute-force list.
  - BOUNDED: a step cap + a per-run call cache (identical calls never re-run).

  boxcutter crawlio https://example.com/app --provider litellm --model "openai/gpt-5.1" --api-key ... --base-url ...
  boxcutter crawlio https://example.com --context "auth: send Cookie: session=abc; /billing is out of scope"

Output items: {url, method, note[, params, req_body, content_type]} - the verified, deduped, in-scope endpoints.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import re
import string
import sys
from urllib.parse import parse_qsl, urlparse

from ..core import agentlog
from ..core.envelope import debug_logger, debug_print, harvest_images, output_result, write_report
from ..irvin import briefing
from ..irvin.context import extract_json
from ..irvin.provider import PROVIDERS, add_agent_args
from ..tools import toolschema

NAME = "crawlio"
KIND = "items"
HELP = "Single-agent crawler: build a comprehensive, code-verified endpoint list (strict about false/ghost paths)."

# TRUSTED tools OBSERVE real behaviour (links, specs, XHR, JS refs, real request flows) or SELF-VERIFY
# (path-bust applies its own content/structure catch-all gate). There is no raw-guessing brute tool anymore, so
# no UNTRUSTED set. visual-driver is TRUSTED for the api FLOWS it captures - they are real requests the page
# actually made while a human-like session drove it.
_TRUSTED = {"katana-crawl", "swagger-specs", "swagger-endpoints", "browser-crawl", "js-endpoints", "screenshot",
            "path-bust", "visual-driver"}
_TOOLS = sorted(_TRUSTED | {"http-request"})

_ID_SEG = re.compile(r"\A(?:\d+|[0-9a-fA-F]{8,}|[0-9A-Za-z_-]{20,})\Z")

_SYSTEM = (
    "You are CRAWLIO, a specialist web/API CRAWLER. Your ONE deliverable is a COMPREHENSIVE, DEDUPED list of the "
    "endpoints that ACTUALLY EXIST on the target - judged as much on the FALSE endpoints you keep OUT as on the "
    "real ones you find. Act only through the tools provided (never PUT/PATCH/DELETE, never shell). Reuse the "
    "strongest identity/header on every request. Stay on the target's host and honour the SCOPE in your task: if "
    "a starting PATH is given (e.g. /app), crawl ONLY within that subtree - never its parent or sibling paths.\n\n"

    "FLOW - work in THIS order (deviate only with a reason):\n"
    "  1. SCREENSHOT FIRST: `screenshot <base>` to SEE what the app IS - purpose/stack, and whether it's a real "
    "app or a dead/404/parked page. If it's dead, say so and stop early - there is nothing to crawl.\n"
    "  2. KATANA + CHEAP SOURCES: if the app is alive, `katana-crawl <base>` for the linked surface (TRUSTED), "
    "and check robots.txt / sitemap.xml / .well-known with `http-request` for listed paths.\n"
    "  3. BROWSER + SPEC + JS: ALWAYS `browser-crawl <base>` - render the app and COLLECT the real endpoints it "
    "calls (XHR/fetch, with methods + bodies). This is a PRIMARY endpoint source (not optional, not SPA-only) and "
    "catches the live API surface katana never sees. Then `swagger-specs <host>` -> `swagger-endpoints <spec>` if "
    "a spec exists (TRUSTED - declared API); `js-endpoints <jsfile>` on JS katana finds (references - verify the "
    "ones that matter).\n"
    "  3b. VISION WHEN THE APP IS A RICH SPA: browser-crawl clicks blindly by selector and often barely leaves "
    "the landing shell. If the app only reveals its real API once a HUMAN uses it (type an address and get "
    "results, open a restaurant/product, apply a filter, page a list) - or its controls resist selectors (a map, "
    "a canvas, a CSS-in-JS widget, a bot check) - DRIVE it with `visual-driver` (see the VISION manual below): "
    "SEE each screen and pursue the key user journeys to TRIGGER and CAPTURE the real API flows browser-crawl "
    "missed. This is how you collect the deep surface.\n"
    "  4. BRUTE - BREADTH FIRST: `path-bust <base> --full` - ONE wide sweep with the ~12k breadth list to MAP "
    "where things live. It is SELF-VERIFIED (runs its own catch-all gate), so its hits are real paths, not "
    "guesses. Treat it as your map of the app's directory structure; a partial sweep is fine.\n"
    "  5. TRIAGE THE DELTA + SHORTLIST JUICY FOLDERS: the paths the sweep surfaces that KATANA did NOT are the "
    "unlinked, often INTERESTING stuff. Build a SHORT list of folders worth digging - ONLY ones that plausibly "
    "hold sensitive content (admin, api, internal, private, backup, config, .git/.svn, staging/dev/test, "
    "uploads, logs, db, actuator, debug, secrets, or anything auth-gated 401/403). Explicitly SKIP low-value "
    "static-asset dirs (images, img, css, js, fonts, media, assets, static, vendor, icons). `screenshot` the "
    "ones that look interesting. If any hit is an API SPEC (swagger/openapi/api-docs), MAP it with "
    "`swagger-endpoints` - the spec expands one path into the whole API.\n"
    "  6. DEEPEN THE SHORTLIST: for each folder on your step-5 shortlist (NOT every folder), run "
    "`path-bust <base>/<folder>` with the fast CURATED list (default - NO --full), and recurse only while it "
    "keeps yielding NEW real paths. Breadth once at the top; precision only into the folders that matter.\n\n"

    "TOOLS - what each is for, how to call it, and how far to trust its output. Every tool here OBSERVES real "
    "behaviour or SELF-VERIFIES, so none emits raw ghosts:\n"
    "  - screenshot <url> - SEE the page: purpose, stack, dead-vs-alive. Do this FIRST. "
    "Ex: `screenshot https://site/app`.\n"
    "  - katana-crawl <url> [--js] - the LINKED surface from real hrefs (TRUSTED - observed). "
    "Ex: `katana-crawl https://site`; `katana-crawl https://site --js` to surface JS bundles.\n"
    "  - browser-crawl <url> - render a JS/SPA and capture its routes + real XHR/fetch (TRUSTED - observed). Use "
    "when the page is a blank/SPA shell without JS. Ex: `browser-crawl https://site`.\n"
    "  - visual-driver <url> --session <id> --action '<verb:args>' [--action ...] - DRIVE the app by SCREEN "
    "COORDINATES like a human (VISION): each call returns a gridded screenshot AND the api flows your actions "
    "triggered (TRUSTED - observed). Reuse the SAME --session id every call so page state carries over. Use it to "
    "collect the deep API a rich SPA only exposes once used. Ex: `visual-driver https://site --session crawl "
    "--action wait --action screen`. See the VISION manual.\n"
    "  - js-endpoints <js-url> - pull endpoint REFERENCES out of a JS bundle (LEADS - confirm the ones that "
    "matter with http-request). Ex: `js-endpoints https://site/static/app.js`.\n"
    "  - swagger-specs <host> - probe for an OpenAPI/Swagger spec. Ex: `swagger-specs https://site` -> spec URLs.\n"
    "  - swagger-endpoints <spec-url> - list the endpoints declared IN a found spec (TRUSTED - declared API). "
    "Ex: `swagger-endpoints https://site/openapi.json`.\n"
    "  - path-bust <base> [--full] [--depth N] [--codes 200,401,403] - brute-force UNLINKED paths under <base>; "
    "it runs the content/structure catch-all gate ITSELF so hits are real (SELF-VERIFIED). USE IT CLEVERLY, in "
    "TWO passes: (1) `path-bust <base> --full` ONCE for a wide breadth map of the directory structure, then "
    "(2) `path-bust <base>/<folder>` with the fast curated default to dig PRECISELY into each INTERESTING folder "
    "the sweep revealed - never re-sweep the same place, never --full a subfolder. `--codes 200,401,403` also "
    "flags protected dirs. If a hit is an API SPEC (swagger*, openapi*, api-docs, v2/v3/api-docs, a "
    ".json/.yaml/.wadl spec), do NOT stop at that one path - feed it to `swagger-endpoints` to map the WHOLE "
    "declared API.\n"
    "  - http-request <url> [-D body] [-H 'K: V'] - ONE manual request for spot-checks / seeded paths. "
    "Ex: `http-request https://site/robots.txt`; `http-request https://site/api/login -D '{\"u\":\"a\"}' "
    "-H 'Content-Type: application/json'`.\n\n"

    "VISION MANUAL - DRIVING THE APP BY COORDINATES (visual-driver) to collect the DEEP api surface. Some apps "
    "only call their real API once a human genuinely uses them, and the controls resist selector-clicking (a "
    "canvas, a map, a CSS-in-JS widget, a bot check). Drive them by SCREEN COORDINATES: `visual-driver <base> "
    "--session crawl --action ...` holds ONE PERSISTENT browser session - reuse the SAME --session id on EVERY "
    "call so page state carries over - and each call returns a screenshot with a coordinate GRID (x across the "
    "top, y down the left, labeled every 100px) PLUS the api flows your actions triggered.\n"
    "THE RHYTHM - one interaction at a time: `wait` for the page to settle -> `screen` to SEE it -> READ the "
    "target's x,y off the grid -> `probe:X,Y` to CONFIRM what's there (it reports e.g. `input`, `button "
    "\"Search\"`) -> act -> `wait` -> `screen` again to see the RESULT, then decide the next coordinate. Act "
    "with `click:X,Y`, `put:TEXT` to type into the focused field, `key:Enter`/`key:Tab`, `scroll:down`, or the "
    "`click_text:LABEL` / `fill_text:LABEL=TEXT` shortcuts when the control is a plain DOM node. THE SCREENSHOT "
    "IS YOUR SOURCE OF TRUTH - reading the exact x,y off the grid and clicking it works even where the DOM is "
    "hidden (widget/shadow-DOM/iframe/canvas); guessing pixels WITHOUT looking is what fails. Only chain actions "
    "that stay on the SAME screen; after anything that navigates or reflows, take a NEW `screen` before aiming "
    "again - the page re-renders elements to new positions.\n"
    "FIRST dismiss any cookie/consent/age overlay (`click_text:Accept all`, or probe+click its button) - it sits "
    "on top and blocks every click underneath. THEN pursue the JOURNEYS that light up the API: enter a "
    "location/search term and submit; open a result's detail view; apply a filter; page a list. Use the "
    "`requests` action (or read the flows the call returns) after each journey and fold every NEW real endpoint "
    "(method, url, body) into your list. You are COLLECTING endpoints, NOT logging in or changing state - never "
    "submit a purchase / delete / logout. Stay on the target host. A few PURPOSEFUL journeys beat dozens of "
    "aimless clicks - vision is expensive, so spend it where the API lives.\n"
    "OUTPUT: visual-driver returns a `state` record plus `flows`; every flow's request url+method is a REAL "
    "observed endpoint - treat them exactly like browser-crawl's XHR (deduped, catch-all-checked).\n\n"

    "CATCH-ALL AWARENESS. A 200 is NOT proof of a real path: many hosts route EVERY path through one "
    "front-controller (Caddy try_files, an SPA, an index.php that only reads the query), so a made-up path "
    "returns 200 and the SAME page. path-bust already fingerprints and gates this for its brute results. For any "
    "path YOU keep from a LEAD or spot-check with http-request, apply the same test: compare it against a random "
    "nonexistent path (with the SAME query, if any) - if they render the SAME page it's the front-controller, so "
    "DROP it. When in doubt DROP; a deterministic gate ALSO re-checks your final list against the catch-all, so "
    "padding only costs you.\n\n"

    "DEDUP: collapse id-like path segments to {id} (/user/1, /user/2 -> one) and dedup by (method, path-family + "
    "param NAMES). A feed of 50 items from one template is ONE endpoint.\n\n"

    "GATES - be FAST, never repeat work: never issue a tool call you already made (the runtime caches identical "
    "calls and REFUSES a third repeat); a path enters the list ONLY after it passes the catch-all check; deepen a "
    "dir ONLY if it's interesting and not already dug; when a full pass adds NO new REAL endpoint, STOP.\n\n"

    "NARRATE - before each tool call, say in ONE short sentence WHY you're making it and what you expect it to "
    "tell you (e.g. 'probing the well-known paths for an OpenAPI spec', 'the app is a blank SPA shell so I need "
    "browser-crawl to see its real XHR calls', 'digging the /admin folder the sweep surfaced'). One line, then "
    "call the tool - this keeps the run auditable so a reader can follow your reasoning, not just your commands.\n\n"

    "DELIVERABLE - when the STOP gate is met, END with ONE fenced ```json block and nothing after it. Every "
    "endpoint must be REAL, in-scope, and deduped; carry the method and, for POST/API, the request body/params so "
    "the next stage can fuzz it:\n"
    '{"endpoints":[{"url":"<verified url incl. any param>","method":"GET|POST","note":"why REAL + interesting?",'
    '"params":["name"],"req_body":"<body if POST>","content_type":"<if known>"}],\n'
    ' "dropped":[{"url":"<url>","why":"ghost/catch-all/soft-404/dup"}],\n'
    ' "notes":["scope reached, specs found, dirs deepened, anything the next stage should know"]}')


def _call(argv: list, headers: list) -> str:
    """Run a boxcutter sub-command IN-PROCESS and return its raw stdout (the JSON envelope). stderr streams
    live; only stdout is captured. Auth headers ride every call that accepts a header flag."""
    from ..cli import main as cli_main
    try:
        flag = toolschema.build(argv[0])["flag_of"].get("header") if argv else None
    except Exception:  # noqa: BLE001
        flag = None
    if flag and headers:
        argv = argv + [x for h in headers for x in (flag, h)]
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            cli_main(list(argv))
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"success": False, "error": f"{argv[0]} failed: {exc}"})
    return buf.getvalue().strip()


def _family(url: str) -> str:
    """(host, path with id-segments -> {id}, sorted param NAMES) - the dedup key. /user/1 == /user/2."""
    p = urlparse(url)
    segs = ["{id}" if _ID_SEG.match(s) else s.lower() for s in p.path.strip("/").split("/") if s]
    params = ",".join(sorted({k.lower() for k, _ in parse_qsl(p.query)}))
    return f"{(p.hostname or '').lower()}/{'/'.join(segs)}[{params}]"


def _in_scope(url: str, base_host: str, scope_path: str) -> bool:
    """In scope = the target host and, if a starting PATH was given, ONLY that subtree. Bare host = host-wide."""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if scope_path:
        sp = scope_path.rstrip("/")
        path = p.path or "/"
        return host == base_host and (path == scope_path or path == sp or path.startswith(sp + "/"))
    return host == base_host or host.endswith("." + base_host)


def _cap(raw: str, max_items: int = 60, max_chars: int = 9000) -> str:
    """Bound a tool result before it re-enters the model's history: keep as many WHOLE data items as fit the
    char budget (so a katana/path-bust that returns hundreds of URLs can't blow up the context window) - and
    NEVER emit truncated/invalid JSON."""
    if len(raw) <= max_chars:
        return raw
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return raw[:max_chars] + f"\n...[truncated {len(raw) - max_chars} chars]"
    data = env.get("data")
    if isinstance(data, list) and data:
        n = min(len(data), max_items)
        while n > 0:                                   # shrink the list until the whole envelope fits
            trial = dict(env)
            trial["data"] = data[:n]
            if n < len(data):
                trial["_truncated"] = f"showing {n} of {len(data)} items"
            s = json.dumps(trial)
            if len(s) <= max_chars:
                return s
            n -= max(1, n // 8)
    return raw[:max_chars] + "\n...[truncated]"


def _bound_timeout(argv: list, slot: int) -> list:
    """path-bust runs as one BLOCKING call, so cap its --timeout to `slot` seconds - a --full sweep otherwise
    runs to path-bust's own 1200s default and can overrun the crawl. Honours a smaller --timeout the agent set,
    but never lets it exceed the slot."""
    out, i, seen = [], 0, False
    while i < len(argv):
        if argv[i] == "--timeout" and i + 1 < len(argv):
            try:
                val = min(int(argv[i + 1]), slot)
            except (TypeError, ValueError):
                val = slot
            out += ["--timeout", str(val)]
            seen = True
            i += 2
            continue
        out.append(argv[i])
        i += 1
    if not seen:
        out += ["--timeout", str(slot)]
    return out


def _compact_pathbust(raw: str) -> str:
    """Slim path-bust findings to the fields the agent needs to SELECT folders/endpoints (url, status, size,
    title), dropping the verbose info/loc/aliases, so far more of a --full breadth sweep survives _cap."""
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return raw
    data = env.get("data")
    if not isinstance(data, list):
        return raw
    slim = []
    for d in data:
        if isinstance(d, dict) and d.get("url"):
            item = {"url": d["url"], "status": d.get("status"), "size": d.get("size")}
            if d.get("page_title"):
                item["title"] = d["page_title"]
            slim.append(item)
    env["data"] = slim
    return json.dumps(env)


def _absorb(raw: str, tool: str, base_host: str, scope_path: str, candidates: set) -> None:
    """Safety net: collect IN-SCOPE URLs a TRUSTED tool reported (path-bust self-gates, so its verified paths
    are safe here too). Backs the fallback if the agent never finalizes; the agent still owns the primary output."""
    if tool not in _TRUSTED:
        return
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return
    data = env.get("data") if isinstance(env, dict) and isinstance(env.get("data"), list) else []
    for d in data:
        u = d.get("url") if isinstance(d, dict) else (d if isinstance(d, str) else None)
        if isinstance(d, dict) and isinstance(d.get("status"), int) and d["status"] in (400, 404, 410, 501):
            continue
        if isinstance(u, str) and u.startswith(("http://", "https://")) and _in_scope(u, base_host, scope_path):
            candidates.add(u)


# -- deterministic ghost gate ------------------------------------------------

def _fetch(url: str, headers: list, cache: dict) -> dict:
    key = ("http-request", url)
    if key not in cache:
        cache[key] = _call(["http-request", url], headers)
    try:
        d = (json.loads(cache[key]).get("data") or [{}])[0]
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _sig(item: dict) -> tuple:
    """A response signature robust to tiny differences: (status, title, length-bucket)."""
    return (item.get("status"), (item.get("title") or "")[:80], len(str(item.get("content") or "")) // 64)


def _rand_url(base_url: str, query: str = "") -> str:
    r = "zzq-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return base_url.rstrip("/") + "/" + r + (("?" + query) if query else "")


def _ghost_gate(items: list, base_url: str, headers: list, cap: int = 120) -> tuple:
    """Re-verify the crawl's endpoints against the host's catch-all behaviour IN CODE. If the host honestly
    404s, every listed path is trusted. If it's a catch-all, drop any endpoint whose (bare, and query-control)
    response is indistinguishable from the front-controller. Returns (kept, dropped)."""
    cache: dict = {}
    a, b = _fetch(_rand_url(base_url), headers, cache), _fetch(_rand_url(base_url), headers, cache)
    catch_all = a.get("status") == 200 and _sig(a) == _sig(b)
    if not catch_all:
        return items, []                       # host 404s on nonsense -> a listed path is real; trust the crawl
    kept, dropped, sa = [], [], _sig(a)
    for it in items[:cap]:
        url = it["url"]
        p = urlparse(url)
        if not p.path.strip("/"):
            kept.append(it)                     # root is always real
            continue
        bare = f"{p.scheme}://{p.hostname}{p.path}"
        if _sig(_fetch(bare, headers, cache)) != sa:
            kept.append(it)                     # the PATH itself differs from the catch-all -> real
            continue
        if not p.query:
            dropped.append({"url": url, "why": "bare path == catch-all (ghost)"})
            continue
        ctrl = _fetch(_rand_url(base_url, p.query), headers, cache)
        if _sig(_fetch(url, headers, cache)) == _sig(ctrl):
            dropped.append({"url": url, "why": "query-driven; path == random?same-query (ghost)"})
        else:
            kept.append(it)
    kept += items[cap:]                          # beyond the cap: keep (don't over-drop a huge list), noted below
    return kept, dropped


# -- cli ---------------------------------------------------------------------

def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL or host (the app root)")
    add_agent_args(parser, max_steps=40)


def _target_url(argv: list) -> str:
    for a in argv[1:]:
        if isinstance(a, str) and a.startswith(("http://", "https://")):
            return a
    return ""


def _has_final(text: str) -> bool:
    o = extract_json(text)
    return isinstance(o, dict) and isinstance(o.get("endpoints"), list)


def run(args) -> int:
    target = args.target.strip()
    if not target:
        output_result([], args.output, "a target is required")
        return 2
    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"crawlio: provide --api-key or set {provider_cls.env} for --provider {args.provider}\n")
        return 2

    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    base_host = (urlparse(base_url).hostname or "").lower()
    scope_path = urlparse(base_url).path or ""
    if scope_path in ("", "/"):
        scope_path = ""
    headers = list(args.header or [])
    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)

    focus = ""
    if args.context.strip():
        cfg = briefing.parse(provider, args.context, base_host)
        headers += cfg.get("headers", [])
        focus = cfg.get("focus") or args.context.strip()
        if cfg.get("headers"):
            sys.stderr.write("crawlio :: auth header(s) parsed from --context (values hidden)\n")

    tools_spec = toolschema.native_tools(_TOOLS)
    scope_note = (f"SCOPE: crawl ONLY under {base_url} - paths starting with {scope_path} (never parent/sibling "
                  "paths).\n" if scope_path else f"SCOPE: the whole host {base_host}.\n")
    user = (f"TARGET: {base_url}\n" + scope_note + (f"BRIEFING: {focus}\n" if focus else "") +
            "Follow the FLOW: screenshot, katana, ALWAYS browser-crawl (collect real XHR/fetch endpoints), "
            "spec/JS, then a breadth `path-bust --full` sweep, pick the interesting folders, and dig into each "
            "precisely with the curated list. Emit the json list when the STOP gate is met.")
    messages = [{"role": "user", "content": user}]
    candidates: set = set()
    cache, count = {}, {}
    final_json = ""
    nudged = False
    dbg = debug_logger(args.debug)          # verbose tier: the WHY + per-call outcomes, only under --debug

    for _ in range(max(1, args.max_steps)):
        try:
            resp = provider.send(_SYSTEM, messages, tools_spec)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"crawlio: provider error: {exc}\n")
            break
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        if text.strip():
            if _has_final(text):
                final_json = text                 # keep the LAST real json, even if the model talks after it
            # the model's own words are the "why" behind the calls in this turn: a short line always, the FULL
            # rationale (untruncated) under --debug so a long narration isn't clipped mid-reason.
            flat = " ".join(text.split())
            if args.debug:
                dbg("crawlio: " + flat)
            else:
                debug_print("crawlio> " + flat[:220])
        if not calls:
            if final_json:
                break
            if not nudged:                          # a chatty first turn shouldn't end the run
                nudged = True
                messages.append({"role": "user", "content": "Use the tools now - start with `screenshot` of the "
                                 "base, then `katana-crawl`. Do not answer in prose without acting."})
                continue
            break
        results = []
        for c in calls:
            if c["name"] not in _TOOLS:
                results.append({"id": c["id"], "output": json.dumps({"error": f"{c['name']} not available"}),
                                "images": []})
                continue
            argv = toolschema.to_argv(c["name"], c["args"])
            tgt = _target_url(argv)
            if tgt and not _in_scope(tgt, base_host, scope_path):     # runtime scope guard on dispatch
                raw = json.dumps({"success": False, "error": f"{tgt} is OUT OF SCOPE - stay under {base_url}"})
                dbg(f"    x REFUSED (out of scope): {tgt} is not under {base_url}")
            else:
                key = tuple(argv)
                # a visual-driver call carrying --session is STATEFUL: the SAME argv at two different moments
                # drives a browser that has MOVED ON (navigated, opened a modal, scrolled), so it must NOT be
                # served from cache or gated as a "repeat" the way a pure read (an http GET, a katana crawl) can.
                stateful = c["name"] == "visual-driver" or "--session" in argv
                count[key] = count.get(key, 0) + 1
                if not stateful and count[key] > 2:
                    raw = json.dumps({"success": False,
                                      "error": "already ran this exact call - reuse the earlier result, do not repeat"})
                    dbg(f"    x REFUSED (repeat): {c['name']} already ran twice - reusing earlier result")
                elif not stateful and key in cache:
                    raw = cache[key]
                    dbg(f"    (cache hit) {c['name']}: reusing the earlier result for this exact call")
                else:
                    run_argv = argv
                    if c["name"] == "path-bust":       # blocking call -> cap it with a fixed per-call timeout
                        run_argv = _bound_timeout(argv, 300)
                    # forward --debug so the sub-tool streams its OWN diagnostics to stderr (browser-crawl's
                    # 'N api calls, landed on <url>', visual-driver's 'N ok / M failed, K flow(s)' - the detail
                    # that shows whether it rendered/drove the app or got blocked). Dispatched argv only; the
                    # cache key stays the clean argv above.
                    run_argv = agentlog.forward_debug(run_argv, args.debug)
                    debug_print("crawlio> boxcutter " + " ".join(str(a) for a in run_argv))
                    raw = _call(run_argv, headers)
                    if c["name"] == "path-bust":
                        raw = _compact_pathbust(raw)   # slim findings so a --full sweep survives the context cap
                    if not stateful:
                        cache[key] = raw
                    _absorb(raw, c["name"], base_host, scope_path, candidates)
                    dbg(f"    <- {c['name']}: {agentlog.summarize(raw)}")
            is_pb = c["name"] == "path-bust"
            clean, images = harvest_images(
                _cap(raw, max_items=150 if is_pb else 60, max_chars=12000 if is_pb else 9000), max_images=4)
            results.append({"id": c["id"], "output": clean, "images": images})
        messages += provider.tool_results(results)

    # -- assemble: agent list (or trusted-only fallback) -> dedup+scope -> deterministic ghost gate -----------
    obj = extract_json(final_json)
    agent_eps = obj.get("endpoints") if isinstance(obj.get("endpoints"), list) else []
    items, seen = [], set()

    def _add(url, method, note, extra):
        if not (isinstance(url, str) and url.startswith(("http://", "https://")) and _in_scope(url, base_host, scope_path)):
            return
        fam = (str(method).upper(), _family(url))
        if fam in seen:
            return
        seen.add(fam)
        items.append({"url": url, "method": str(method).upper(), "note": note, **extra})

    for e in agent_eps:
        if isinstance(e, dict):
            extra = {k: e[k] for k in ("params", "req_body", "content_type") if e.get(k)}
            _add(e.get("url"), e.get("method", "GET"), e.get("note", ""), extra)
    if not items:
        debug_print("crawlio :: agent emitted no final list - falling back to TRUSTED-tool URLs only")
        for u in sorted(candidates):
            _add(u, "GET", "auto-collected from a trusted tool (agent did not finalize)", {})

    items, ghosts = _ghost_gate(items, base_url, headers)
    agent_dropped = obj.get("dropped") if isinstance(obj.get("dropped"), list) else []
    debug_print(f"\ncrawlio :: {len(items)} verified endpoint(s); ghost-gate dropped {len(ghosts)}; "
                f"agent dropped {len(agent_dropped)} ({len(candidates)} trusted candidates seen)")
    for g in ghosts[:10]:
        debug_print(f"  ghost: {g['url']} - {g['why']}")
    report = "\n".join([f"## Crawlio - endpoints: {base_url}", "", f"{len(items)} verified endpoint(s):", ""]
                       + [f"- {it.get('method', 'GET')} {it.get('url', '')}" for it in items])
    write_report(getattr(args, "report", None), report)
    output_result(items, args.output)
    return 0

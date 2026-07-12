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
  - BOUNDED: a wall-clock budget + step cap + a per-run call cache (identical calls never re-run).

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
import time
from urllib.parse import parse_qsl, urlparse

from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_print, harvest_images, output_result
from ..irvin import briefing
from ..irvin.context import extract_json
from ..irvin.provider import PROVIDERS, add_ai_provider_args
from ..tools import toolschema

NAME = "crawlio"
KIND = "items"
HELP = "Single-agent crawler: build a comprehensive, code-verified endpoint list (strict about false/ghost paths)."

# TRUSTED tools OBSERVE real behaviour (links, specs, XHR, JS refs) or SELF-VERIFY (path-bust applies its own
# content/structure catch-all gate). There is no raw-guessing brute tool anymore, so no UNTRUSTED set.
_TRUSTED = {"katana-crawl", "swagger-specs", "swagger-endpoints", "browser-crawl", "js-endpoints", "screenshot",
            "path-bust"}
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
    "  3. SPEC + SPA + JS: `swagger-specs <host>` then `swagger-endpoints <spec>` if a spec exists (TRUSTED); "
    "`browser-crawl <base>` if it's a JS/SPA (TRUSTED - real XHR); `js-endpoints <jsfile>` on JS katana finds "
    "(references - verify the ones that matter).\n"
    "  4. BRUTE (SELF-VERIFIED): `path-bust <base>` for UNLINKED paths. It applies the content/structure "
    "catch-all gate INTERNALLY, so its hits are already REAL paths, not raw guesses. Fast curated list by "
    "default; add --full for the ~12k breadth list when a target earns a deep sweep.\n"
    "  5. TRIAGE THE DELTA: the paths `path-bust` surfaces that KATANA did NOT are the unlinked, often "
    "INTERESTING stuff. Analyze that delta and `screenshot` any that look interesting (admin, test, debug, dev, "
    "staging, internal, panel, backup, api). If any hit is an API SPEC (swagger/openapi/api-docs), MAP it with "
    "`swagger-endpoints` before moving on - the spec expands one path into the whole API.\n"
    "  6. ENUMERATE DEEPER: if an interesting directory is confirmed, run `path-bust <base>/<dir>` into it (or "
    "`path-bust <base> --depth N`) and recurse while it keeps yielding.\n\n"

    "TOOLS - what each is for, how to call it, and how far to trust its output. Every tool here OBSERVES real "
    "behaviour or SELF-VERIFIES, so none emits raw ghosts:\n"
    "  - screenshot <url> - SEE the page: purpose, stack, dead-vs-alive. Do this FIRST. "
    "Ex: `screenshot https://site/app`.\n"
    "  - katana-crawl <url> [--js] - the LINKED surface from real hrefs (TRUSTED - observed). "
    "Ex: `katana-crawl https://site`; `katana-crawl https://site --js` to surface JS bundles.\n"
    "  - browser-crawl <url> - render a JS/SPA and capture its routes + real XHR/fetch (TRUSTED - observed). Use "
    "when the page is a blank/SPA shell without JS. Ex: `browser-crawl https://site`.\n"
    "  - js-endpoints <js-url> - pull endpoint REFERENCES out of a JS bundle (LEADS - confirm the ones that "
    "matter with http-request). Ex: `js-endpoints https://site/static/app.js`.\n"
    "  - swagger-specs <host> - probe for an OpenAPI/Swagger spec. Ex: `swagger-specs https://site` -> spec URLs.\n"
    "  - swagger-endpoints <spec-url> - list the endpoints declared IN a found spec (TRUSTED - declared API). "
    "Ex: `swagger-endpoints https://site/openapi.json`.\n"
    "  - path-bust <base> [--full] [--depth N] [--codes 200,401,403] - brute-force UNLINKED paths under <base>; "
    "it runs the content/structure catch-all gate ITSELF so hits are real (SELF-VERIFIED - trust the hits, still "
    "triage for interest). Ex: `path-bust https://site` (fast), `path-bust https://site --full` (deep ~12k), "
    "`path-bust https://site/admin --depth 1` (dig into a dir), `path-bust https://site --codes 200,401,403` "
    "(also flag protected dirs). If a hit is an API SPEC (swagger*, openapi*, api-docs, v2/v3/api-docs, a "
    ".json/.yaml/.wadl spec), do NOT stop at that one path - feed it to `swagger-endpoints` to map the WHOLE "
    "declared API.\n"
    "  - http-request <url> [-D body] [-H 'K: V'] - ONE manual request for spot-checks / seeded paths. "
    "Ex: `http-request https://site/robots.txt`; `http-request https://site/api/login -D '{\"u\":\"a\"}' "
    "-H 'Content-Type: application/json'`.\n\n"

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
    """Bound a tool result before it re-enters the model's history: trim the data list + note it, so a katana/
    path-bust that returns hundreds of URLs doesn't blow up the context window (the deaths of 'full memory')."""
    if len(raw) <= max_chars:
        return raw
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return raw[:max_chars] + f"\n...[truncated {len(raw) - max_chars} chars]"
    data = env.get("data")
    if isinstance(data, list) and len(data) > max_items:
        env["data"] = data[:max_items]
        env["_truncated"] = f"showing {max_items} of {len(data)} items"
        s = json.dumps(env)
        return s if len(s) <= max_chars else s[:max_chars]
    return raw[:max_chars] + "\n...[truncated]"


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
    parser.add_argument("--context", default="", metavar="TEXT",
                        help="Free-text briefing: scope, out-of-scope areas, and any auth header/token to send")
    add_ai_provider_args(parser)          # --provider/--model/--api-key/--base-url
    parser.add_argument("--max-steps", dest="max_steps", type=int, default=40, help="Hard cap on agent steps")
    parser.add_argument("--budget", type=int, default=900, help="Wall-clock budget in seconds (then finalize)")
    add_header_arg(parser)
    add_common_args(parser)


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
            "Follow the FLOW: screenshot, katana, spec/SPA/JS, then path-bust for unlinked paths, triage the "
            "delta, deepen. Emit the json list when the STOP gate is met.")
    messages = [{"role": "user", "content": user}]
    candidates: set = set()
    cache, count = {}, {}
    final_json = ""
    nudged = False
    deadline = time.time() + max(30, args.budget)

    for _ in range(max(1, args.max_steps)):
        if time.time() > deadline:
            debug_print("crawlio :: wall-clock budget reached - finalizing with what's mapped")
            break
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
            debug_print("crawlio> " + text.strip()[:220])
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
            else:
                key = tuple(argv)
                count[key] = count.get(key, 0) + 1
                if count[key] > 2:
                    raw = json.dumps({"success": False,
                                      "error": "already ran this exact call - reuse the earlier result, do not repeat"})
                elif key in cache:
                    raw = cache[key]
                else:
                    debug_print("crawlio> boxcutter " + " ".join(str(a) for a in argv))
                    raw = _call(argv, headers)
                    cache[key] = raw
                    _absorb(raw, c["name"], base_host, scope_path, candidates)
            clean, images = harvest_images(_cap(raw), max_images=4)
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
    output_result(items, args.output)
    return 0

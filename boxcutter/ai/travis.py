"""travis - a RECON TRIAGE agent (bob's scout). Built as an autonomous LLM agent, like bob.

You HAND travis ONE host (a subdomain or URL). Its one job: with a FEW light requests, UNDERSTAND what the host
is and decide whether it is worth a deeper AUTOMATED scan (bob) and/or a human SECURITY ENGINEER's review - and
explain it clearly enough that a human can prioritise. THE MISSION: catch debug / admin / test / internal /
"weird" functionality that should NOT be exposed to the public (an open Swagger/OpenAPI UI, an actuator/debug
console, an admin panel, a staging/test feature, a metrics/health dashboard, verbose errors) before it ships.
It is a scoping/triage pass, not a scanner - read, explore, judge, rank. One host per invocation, like the
other agents.

The AGENT drives: it READS and understands the content - http-request the root - and reaches for httpx (a quick
liveness/tech probe), a screenshot, VISUAL-DRIVER (to interactively click through an app and reveal what
functionality it exposes), swagger-specs/graphql-detect (to confirm an API surface), or dnsx when it needs
more. The model does the judging, from CONTENT not the name.

Looping travis over a big host list (and running bob on the ones travis rates worth exploring) is the job of
whatever orchestrates it - travis itself stays single-target, so each host is its own clean, isolated run.

STRICT: travis only ever invokes the DEFINED boxcutter sub-commands in `_TOOLS` (`_call` refuses anything else),
and never path-busts, fuzzes, or runs vuln templates - that is bob's job, on a host travis rates worth it.

  boxcutter travis admin.example.com --provider litellm --api-key ... --model ...
  boxcutter travis https://api.example.com --context "auth: Cookie: session=abc" --table --report travis.md
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from urllib.parse import urlparse

from ..core import agentlog
from ..core.envelope import debug_print, harvest_images, output_result
from ..irvin import briefing
from ..irvin.context import extract_json
from ..irvin.provider import PROVIDERS, add_agent_args
from ..tools import toolschema

NAME = "travis"
KIND = "items"
HELP = "Travis - recon triage: probe ONE host lightly and rate how interesting it is for a deeper scan (bob)."

# NON-INTRUSIVE recon only - read/understand a page, probe liveness/tech, SEE it, resolve DNS, peek at archives,
# and detect an API surface (spec/GraphQL/JS endpoints). NO enumeration (subfinder) and NO scanning or state
# change (path-bust/fuzz/nuclei/sqlmap) - travis scopes, bob scans.
_TOOLS = ["http-request", "httpx", "screenshot", "visual-driver", "dnsx", "wayback",
          "swagger-specs", "graphql-detect", "js-endpoints"]

_INTEREST_RANK = {"high": 0, "medium": 1, "low": 2, "skip": 3}

_SYSTEM = (
    "You are TRAVIS, a RECON TRIAGE agent - bob's scout. You are given ONE host. Your job: with a FEW light "
    "requests, UNDERSTAND what the host is and decide whether it is worth a deeper AUTOMATED scan (bob) and/or a "
    "human SECURITY ENGINEER's review - and explain it clearly enough that a human can prioritise. THE MISSION: "
    "catch debug / admin / test / internal / 'weird' functionality that should NOT be exposed to the public - an "
    "open Swagger/OpenAPI UI, an actuator/debug/metrics/health console, an admin panel, a staging/test feature, "
    "verbose errors / stack traces - and flag it before it ships. You are a SCOPING pass, not a scanner: NO path "
    "brute-force, NO fuzzing, NO vuln templates - read, EXPLORE, judge, rank. Act only through the tools; never "
    "PUT/PATCH/DELETE; stay on the given host.\n\n"

    "TOOLS (the only things you may call - all NON-INTRUSIVE):\n"
    "  - http-request <url> - your MAIN tool: fetch the host's page and READ it to understand what it is (status, "
    "title, server header, and the HTML: login form? admin dashboard? API/JSON? marketing page? error?). Start "
    "here.\n"
    "  - httpx <host> - a quick liveness/tech probe (live service, scheme/port, server version). Use it when a "
    "plain fetch is inconclusive; you do NOT need it if http-request already told you what the host is.\n"
    "  - screenshot <url> - RENDER the page in headless chromium and SEE it (you get the image back). The "
    "fastest way to understand a promising or ambiguous host - an admin dashboard, a login portal, a data table, "
    "or a plain marketing page is obvious at a glance, and it works for a JS/SPA whose raw HTML is an empty "
    "shell. You have a LIMITED screenshot budget - use it when SEEING the page decides the call.\n"
    "  - visual-driver <url> --action ... - drive the page in a REAL browser and INTERACT with it: click "
    "buttons, open menus, follow nav links, fill and submit a form, scroll - to reveal what FUNCTIONALITY the "
    "host actually exposes (an admin action behind a tile, a debug/console page, a data table, a test feature) "
    "that a single screenshot won't show. Prefer the TEXT verbs (click_text:TEXT, find:TEXT, fill_text:LABEL="
    "TEXT) so you needn't read coordinates; add `screen` actions to capture what you see (returned to you as "
    "images) and `requests:api` to see the API calls the page fires. Use it on an APP-looking host worth "
    "exploring - a few actions, not a full crawl; it is the costly tool.\n"
    "  - dnsx <host> - resolve it (A/AAAA/CNAME). A CNAME to a cloud provider (s3/azure/github/heroku/...) or a "
    "dangling record is itself interesting (infra / possible takeover).\n"
    "  - swagger-specs <host> - probe well-known paths for an OpenAPI/Swagger spec; a spec that LOADS = a real, "
    "CONFIRMED API surface (High). graphql-detect <host> - probe for a GraphQL endpoint. Run these on an "
    "API-looking host to actually confirm the surface before you call it High.\n"
    "  - js-endpoints <js-url> - pull endpoint references out of the host's JS bundle (from a <script src>) - "
    "shows whether it's a rich app with its own API. One fetch.\n"
    "  - wayback <host> - historical URLs the host served. Use SPARINGLY, only if you still can't classify it.\n\n"

    "METHOD (light - a few requests):\n"
    "1. READ the host - http-request the root to understand WHAT it is (status, title, tech, the shape of the "
    "page). Fall back to httpx for a quick liveness/tech check only if the fetch is inconclusive.\n"
    "2. On a LIVE host, spend a FEW MORE quick one-shot checks (fast - NOT a crawl) to see what it actually "
    "exposes; a first impression off the home page is not enough:\n"
    "   - swagger-specs AND graphql-detect - map the API surface (note an exposed spec/GraphQL as attack "
    "surface, but a public Swagger is common and is NOT by itself a High - rate by what the API exposes);\n"
    "   - js-endpoints on the main <script src> bundle - what backend API does the app call;\n"
    "   - SCREENSHOT a login/dashboard/app to SEE it.\n"
    "   Reach for VISUAL-DRIVER (the slow interactive tool) ONLY when a promising host is still unclear after "
    "the simple checks - e.g. to click past a login. dnsx for a dangling-CNAME takeover; wayback only if still "
    "unclassifiable. Do NOT probe exposure paths (/.git, /.env, /actuator, /metrics, ...) or brute-force paths "
    "- that is bob's SCAN, not travis's triage.\n"
    "3. RANK from what you CONFIRMED (never a first glance or the name). Stay FAST: a handful of cheap calls, "
    "then finalize.\n\n"

    "RATE FROM CONFIRMED CONTENT, NOT THE NAME. The hostname (api.*, admin.*, ...) only tells you where to LOOK "
    "- it is NEVER the rating. The rating comes from what the CONTENT actually showed: a page you saw, a spec/"
    "endpoint you confirmed, real data returned. A name plus a block/error page is NOT a confirmation, and your "
    "`why` must describe what you SAW, never a surface you're inferring from the name.\n"
    "  THE BASELINE - this is NOT High, it is what almost EVERY live API returns to an unauthenticated probe: "
    "401/403 'auth required' (with or without a Cloudflare/WAF page), a bare or generic 404 JSON at '/', a 426 "
    "'Upgrade Required' from a WebSocket gateway, a 5xx/502/503 gateway error, a captcha/anti-bot wall, a "
    "default server / 'it works' page, an S3 NoSuchKey/AccessDenied. Each only tells you 'a server is here and "
    "it wants auth / has no root route / is erroring' - it confirms the host EXISTS and NOTHING about an exposed "
    "surface. NEVER write a `why` that upgrades a status code into a finding ('confirming API surface', 'REST "
    "service', 'WebSocket gateway', 'payments endpoint') - that is inventing an opportunity out of nothing.\n"
    "  - HIGH: a rendered admin / operations / management / console / dashboard PANEL (e.g. a 'create "
    "restaurant / manage orders / courier ops' UI) - a publicly reachable admin panel IS the finding; do NOT "
    "downgrade it because you couldn't confirm each action works without auth. Also High: a login/SSO/IdP "
    "portal you rendered; an endpoint returning REAL data with NO auth; a directory listing / exposed config / "
    "secret / actuator-env / debug / stacktrace page; interactive debug/test functionality you reached by "
    "clicking; or a dangling-CNAME takeover candidate. (An exposed Swagger/OpenAPI UI or a reachable GraphQL "
    "endpoint is attack SURFACE worth noting, but is NOT by itself a High.)\n"
    "  - MEDIUM - the DEFAULT for anything live and non-trivial you can't confirm is High: a generic login/app "
    "you can't see behind and can't tell is privileged; an auth-gated API (401/403); an exposed Swagger/OpenAPI "
    "UI or GraphQL endpoint; a staging/dev/internal host; a real app (not just marketing). If it's live and "
    "non-trivial but not a clear High, it's Medium.\n"
    "  - LOW: marketing/landing, a redirect to the main site, CDN-only, a static asset host, a parked page, a "
    "bare error/default page, or an unrendered SPA shell / microfrontend placeholder with nothing behind it.\n"
    "  - SKIP: not live - NXDOMAIN, connection refused, TLS handshake failure, connection reset, timeout.\n\n"

    "FAST BUT NOT LAZY: don't crawl, don't brute-force, don't fuzz, don't repeat a call - but DO fire the few "
    "quick checks above on a live host before finalizing (a handful of extra one-shot calls is cheap and makes "
    "the triage worth reading). Don't stop at 'it's a login portal' - do the simple checks first. A clearly "
    "boring host (marketing/redirect/parked/404/dead) needs none of this - classify it and move on.\n\n"

    "FINISH: reply with NO tool call and ONE fenced ```json block (nothing else), EXACTLY these fields - TRAVIS "
    "renders the report from it, so you supply the CONTENT, not the layout:\n"
    "```json\n"
    "{\n"
    '  "interest": "High|Medium|Low|Skip",\n'
    '  "looks_like": "<short label: admin panel / staging API / Swagger UI / marketing / not live / ...>",\n'
    '  "assessment": "<2-4 sentences FOR A HUMAN ENGINEER: what the host is and does, what functionality/'
    'surface it actually exposes (from what you SAW, not the name), and why it does or does not warrant a '
    'closer look>",\n'
    '  "concerns": ["<each specific thing that probably should NOT be public: exposed Swagger UI, a debug/'
    'actuator console, an admin action, a test/staging feature, verbose errors, leaked config - [] if none>"],\n'
    '  "status": <int or null>,\n'
    '  "tech": "<server/framework or empty>",\n'
    '  "recommend": "<one of: automated-scan (hand to bob) / human-review (an engineer should look) / skip - '
    'plus a short why>"\n'
    "}\n```")


def _call(argv: list, headers: list, debug: bool = False) -> str:
    """Run a DEFINED boxcutter sub-command IN-PROCESS and return its raw stdout (the JSON envelope). A tool
    outside the allowlist is refused; header-capable tools get the operator's --header(s) appended; a missing
    binary / failure returns an error envelope, never raises."""
    if not argv or argv[0] not in _TOOLS:
        return json.dumps({"success": False, "error": f"{argv[0] if argv else '?'} is not a defined travis tool"})
    from ..cli import main as cli_main
    try:
        flag = toolschema.build(argv[0])["flag_of"].get("header")
    except Exception:  # noqa: BLE001
        flag = None
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
        return json.dumps({"success": False, "error": f"{argv[0]} failed: {exc}"})
    return buf.getvalue().strip()


def _cap(raw: str, max_chars: int = 7000, max_items: int = 50) -> str:
    """Bound a tool result before it re-enters the model's context (cost control): keep as many WHOLE data items
    as fit, never emit truncated JSON."""
    if len(raw) <= max_chars:
        return raw
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return raw[:max_chars] + "\n...[truncated]"
    data = env.get("data")
    if isinstance(data, list) and data:
        n = min(len(data), max_items)
        while n > 0:
            trial = dict(env)
            trial["data"] = data[:n]
            if n < len(data):
                trial["_truncated"] = f"showing {n} of {len(data)} items"
            s = json.dumps(trial)
            if len(s) <= max_chars:
                return s
            n -= max(1, n // 8)
    return raw[:max_chars] + "\n...[truncated]"


def _harvest_screenshot(raw: str) -> tuple:
    """screenshot returns the PNG INLINE as base64 in the `image` field. Pull it OUT and hand it to the model as
    a real vision block, replacing the blob with a short placeholder so it doesn't flood the context (and so
    _cap doesn't mangle the base64). Returns (clean_text, images)."""
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return raw, []
    data = env.get("data")
    if not isinstance(data, list):
        return raw, []
    images = []
    for d in data:
        if isinstance(d, dict) and isinstance(d.get("image"), str) and len(d["image"]) > 100:
            images.append({"media_type": "image/png", "data": d["image"]})
            d["image"] = f"<screenshot #{len(images)} - shown to you as an image below>"
    return (json.dumps(env), images) if images else (raw, [])


def _triage(provider, target_url: str, host: str, headers: list, tools_spec: list, args) -> tuple:
    """The bounded tool-calling loop for ONE host: the agent reads/understands it (http-request first; httpx/
    screenshot/swagger/graphql/dnsx only when it needs more) and returns its verdict json. Returns
    (verdict_dict, steps)."""
    user = (f"HOST TO TRIAGE: {host}\nURL: {target_url}\n\n"
            "Read and understand this host - http-request its root first; use screenshot / httpx / swagger-specs "
            "/ graphql-detect / dnsx only if you need more to classify it. Then emit the verdict json. Begin.")
    messages = [{"role": "user", "content": user}]

    cache: dict = {}
    count: dict = {}
    used: set = set()                                # tool names actually run (drives the depth-nudge below)
    shots = 0                                        # screenshots taken so far (budget = args.max_screenshots)
    final_text = ""
    nudged = False
    depth_nudged = False
    step = 0

    for step in range(max(1, args.max_steps)):
        try:
            resp = provider.send(_SYSTEM, messages, tools_spec)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"travis: provider error: {exc}\n")
            break
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        if text.strip():
            final_text = text
            debug_print("travis> " + (" ".join(text.split()) if args.debug else " ".join(text.split())[:220]))
        if not calls:
            if final_text.strip() and any(m in final_text for m in ("```json", '"interest"', '"looks_like"')):
                interest = str((extract_json(final_text) or {}).get("interest") or "").lower()
                checks = {"swagger-specs", "graphql-detect", "js-endpoints"}
                if interest in ("high", "medium") and not (used & checks) and not depth_nudged:
                    depth_nudged = True             # a promising host judged off the home page - do the quick checks
                    messages.append({"role": "user", "content":
                        f"You rated this {interest.title()} but only looked at the landing page. Do the quick "
                        "checks first: swagger-specs and graphql-detect (to map the API surface), and "
                        "js-endpoints on its main <script src> to see the backend API. Then re-emit the "
                        "verdict."})
                    continue
                break
            if not nudged:
                nudged = True
                messages.append({"role": "user", "content": "Read the host with the tools - http-request it - "
                                 "then emit the verdict json. Do not answer without reading it."})
                continue
            break
        results = []
        for c in calls:
            if c["name"] not in _TOOLS:
                results.append({"id": c["id"], "output": json.dumps({"error": f"{c['name']} is not a travis tool"})})
                continue
            argv = toolschema.to_argv(c["name"], c["args"])
            used.add(c["name"])
            keyt = tuple(argv)
            count[keyt] = count.get(keyt, 0) + 1
            new_shot = c["name"] == "screenshot" and keyt not in cache      # a NEW capture (the costly one)
            if new_shot and shots >= args.max_screenshots:
                out = json.dumps({"success": False, "error": f"screenshot budget exhausted "
                                  f"({shots}/{args.max_screenshots}) - read this page with http-request instead"})
            elif count[keyt] > 2:
                out = json.dumps({"success": False, "error": "already ran this exact call - reuse the result"})
            elif keyt in cache:
                out = cache[keyt]
            else:
                debug_print("travis> boxcutter " + " ".join(str(a) for a in argv))
                out = _call(argv, headers, args.debug)
                cache[keyt] = out
                if new_shot:
                    shots += 1
            images = []
            if c["name"] == "screenshot":                # forward the PNG as real vision, not a base64 blob
                out, images = _harvest_screenshot(out)
            elif c["name"] == "visual-driver":           # its `screen` shots are temp PNGs - forward as vision
                out, images = harvest_images(out, max_images=6)
            results.append({"id": c["id"], "output": _cap(out), "images": images})
        messages += provider.tool_results(results)

    obj = extract_json(final_text)
    return (obj if isinstance(obj, dict) else {}), step + 1


def _render_report(host: str, row: dict) -> str:
    """Single-host verdict report - ONE labeled field per line so it reads cleanly AND parses cleanly (grep
    `^Interest:` / split on the first `: `). Same field order every run; the fully-structured record for
    programmatic use is the JSON `data[0]` in the envelope."""
    out = [f"## Travis :: {host}", "",
           f"Interest:  {row.get('interest', 'Low')}",
           f"Type:      {row.get('looks_like') or '(unclassified)'}"]
    if row.get("status") not in (None, ""):
        out.append(f"Status:    {row['status']}")
    if row.get("tech"):
        out.append(f"Tech:      {row['tech']}")
    if row.get("url"):
        out.append(f"URL:       {row['url']}")
    if row.get("recommend"):
        out.append(f"Recommend: {str(row['recommend']).strip()}")
    out += ["", "Assessment:", str(row.get("assessment") or "(none)").strip()]
    concerns = row.get("concerns") or []
    out += ["", "Concerns:"] + ([f"- {c}" for c in concerns] if concerns else ["- none"])
    return "\n".join(out)


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target host or URL to triage (e.g. admin.example.com)")
    parser.add_argument("--max-screenshots", dest="max_screenshots", type=int, default=10,
                        help="Cap on how many screenshots travis may take (visual = the costly vision calls); "
                             "past the cap it falls back to http-request. 0 disables screenshots entirely")
    add_agent_args(parser, max_steps=30)


def run(args) -> int:
    target = (args.target or "").strip()
    if not target:
        output_result([], args.output, "travis needs a target host - pass one, e.g. `travis admin.example.com`")
        return 2
    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    host = (urlparse(base_url).hostname or target).lower()

    provider_cls = PROVIDERS[args.provider]          # travis is an LLM agent - a provider/key is MANDATORY
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"travis: an LLM is required - provide --api-key or set {provider_cls.env} "
                         f"for --provider {args.provider}\n")
        return 2
    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)

    headers = list(args.header or [])
    if args.context.strip():
        cfg = briefing.parse(provider, args.context, host)
        headers += cfg.get("headers", []) or []
        if cfg.get("headers"):
            sys.stderr.write("travis :: auth header(s) parsed from --context (values hidden)\n")

    tools_spec = toolschema.native_tools(_TOOLS)
    verdict, steps = _triage(provider, base_url, host, headers, tools_spec, args)

    interest = str(verdict.get("interest") or "Low").strip().title()
    if interest.lower() not in _INTEREST_RANK:
        interest = "Low"
    raw_concerns = verdict.get("concerns")
    concerns = [str(c).strip() for c in raw_concerns if str(c).strip()] if isinstance(raw_concerns, list) else []
    row = {"host": host, "url": base_url, "interest": interest,
           "looks_like": str(verdict.get("looks_like") or "").strip(),
           "assessment": str(verdict.get("assessment") or verdict.get("why") or "").strip(),
           "concerns": concerns,
           "status": verdict.get("status"),
           "tech": str(verdict.get("tech") or "").strip(),
           "recommend": str(verdict.get("recommend") or "").strip()}

    notif = f"[travis] {interest} | {host} | {row['looks_like'] or 'unclassified'}"
    report = _render_report(host, row)
    next_urls = [base_url] if interest.lower() in ("high", "medium") else []

    debug_print(f"\ntravis :: {notif}  ({steps} steps)\n")
    debug_print(report + "\n")

    if getattr(args, "report", None):
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
            debug_print(f"travis :: report written to {args.report}")
        except OSError as exc:
            sys.stderr.write(f"travis: could not write report to {args.report}: {exc}\n")

    extra = {"host": host, "url": base_url, "interest": interest, "report": report,
             "notification": notif, "next": next_urls, "steps": steps}
    if getattr(args, "table", False) and not args.output:
        sys.stdout.write(report + "\n")
    else:
        output_result([row], args.output, extra=extra)
    return 0

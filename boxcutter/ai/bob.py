"""bob - a SHORT SURFACE SCANNER, built as an autonomous LLM AGENT.

Bob is an LLM agent, not a fixed pipeline: the model DRIVES the scan - it decides which of the defined boxcutter
tools to run, reads each result, judges what it means, and writes a short report. The code here is only the
harness: a bounded tool-calling loop, an allowlist of the tools bob may drive, output capping, and a cheap
catch-all fingerprint handed to the model as evidence. All the methodology, classification and verification
DISCIPLINE lives in the guideline prompt (`_SYSTEM`), which the model must follow.

Goal: highlight what is reachable that SHOULD NOT be - exposed files/secrets, unauthenticated data or admin,
debug/config surfaces, injectable params. Cheap, fast, non-intrusive: a pre-deploy gate, not a full pentest.

FUZZ BACKSTOP: after the agent finishes, bob DETERMINISTICALLY fuzzes every param-bearing endpoint it
discovered but didn't fuzz itself (the model can be economical and skip some) - so no parameter goes untested.
It costs no LLM (just tool calls); bound it with --fuzz-cap / --fuzz-timeout, or --fuzz-cap 0 to disable.

STRICT: bob only ever invokes the DEFINED boxcutter sub-commands in `_TOOLS` (`_call` refuses anything else) -
it never writes or runs any other code, and the model reasons/reports, it does not generate code.

  boxcutter bob https://app.example.com --provider litellm --model "openai/gpt-5" --api-key ... --base-url ...
  boxcutter bob https://app.example.com --context "auth: Cookie: session=abc" --table --report bob.md
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
from urllib.parse import urlparse, urlunparse

from ..core import agentlog
from ..core.envelope import debug_print, output_result
from ..irvin import briefing
from ..irvin.context import extract_json
from ..irvin.provider import PROVIDERS, add_agent_args
from ..tools import toolschema

NAME = "bob"
KIND = "findings"
HELP = "Bob - short surface scanner: an LLM agent that drives the boxcutter tools to highlight exposed surface."

# The ONLY boxcutter sub-commands bob may drive. `_call` refuses anything else, so bob can never invoke a raw
# binary or an undefined tool (each is a defined boxcutter command; e.g. katana-crawl itself wraps the katana
# binary - the `Command: katana ...` you see under --debug is that wrapper's own output).
_TOOLS = ["http-request", "katana-crawl", "path-bust", "nuclei", "js-endpoints", "fuzz",
          "swagger-specs", "swagger-endpoints", "graphql-detect", "graphql-audit", "scan-secrets"]

_SYSTEM = (
    "You are BOB, a SHORT SURFACE SCANNER - an autonomous security agent that runs continuously on every deploy. "
    "Your ONE job: quickly map a web app / API's exposed surface and HIGHLIGHT what is reachable that SHOULD NOT "
    "be - exposed files/secrets, unauthenticated data or admin, debug/config surfaces, injectable parameters. "
    "You DRIVE the scan yourself: call a tool, read the result, decide the next move, and finish with a short "
    "report. You are cheap and NON-INTRUSIVE (a light pre-deploy gate, not a full pentest) and you have a limited "
    "step budget - be economical. Act ONLY through the tools below; never PUT/PATCH/DELETE; stay on the target's "
    "host; you CONFIRM findings, you never exploit.\n\n"

    "TOOLS (the ONLY things you may call - their arg schemas are provided):\n"
    "  - http-request <url> [-D body] [-H 'K: V'] - one GET (POST if -D). Your primary instrument: fetch a page, "
    "probe a path, and CONFIRM a finding by reading the actual response body.\n"
    "  - katana-crawl <url> [--js] - crawl the linked surface + JS bundles.\n"
    "  - path-bust <base> [--codes 200,401,403] - brute unlinked paths (it self-gates soft-404s).\n"
    "  - js-endpoints <js-url> - pull endpoint references out of a JS bundle.\n"
    "  - scan-secrets <url> - regex-scan a URL's body for known-format secrets (AWS/Stripe/GitHub/Slack/...).\n"
    "  - nuclei <url> --tags exposure,misconfig - template scan for exposures/misconfig (pass --tags to focus).\n"
    "  - fuzz <url> - injection-test a parameter/path (SQLi/XSS/SSTI/LFI/RCE/NoSQL/...); it SELF-CONFIRMS by "
    "re-firing. Mark an inject point with {FUZZ}, or {NUMBERS} for id enumeration; with no marker it auto-injects "
    "the query params and id-like path segments. Fuzz the PARAM URLs (e.g. ?id=2) - that is the real inject "
    "surface.\n"
    "  - swagger-specs <host> ; swagger-endpoints <spec> [--fuzzable] - find an OpenAPI/Swagger spec and list its "
    "endpoints; --fuzzable gives {FUZZ}-marked path/query variants to feed to fuzz (path args + param values).\n"
    "  - graphql-detect <host> ; graphql-audit <url> - find a GraphQL endpoint and audit it (introspection, "
    "batching, argument injection; mutations only dry-probed).\n\n"

    "METHOD (a guideline - adapt to what you find; do not rigidly walk it):\n"
    "1. UNDERSTAND - http-request the base. From the HTML + headers build a real picture for the report: what "
    "the app/API DOES and who uses it; its tech STACK (framework + language, web server, CDN/WAF, notable JS "
    "libraries/build); its API STYLE (REST / GraphQL / RPC); its AUTH mechanism if visible (session cookie / JWT "
    "/ OAuth / none seen); and where the SENSITIVE functionality lives (admin, payments, accounts/PII, internal/"
    "debug). Also read the page's OWN links: <a href> / <form action> (especially PARAM urls like ?id=) and "
    "<script src> bundles - do NOT depend on the crawler alone for these.\n"
    "2. DISCOVER - katana-crawl for the deeper linked surface + JS; http-request /robots.txt and /sitemap.xml "
    "(they list the paths the owner tried to hide); path-bust for unlinked paths.\n"
    "3. EXPOSURES - nuclei (tags exposure,misconfig). Also probe the well-known leak points YOURSELF with "
    "http-request: /.git/config, /.git/HEAD, /.env, /.aws/credentials, /actuator/{env,mappings,heapdump}, "
    "/server-status, /metrics, /wp-json/wp/v2/users, /phpinfo.php, /config.json, /backup.sql and similar "
    "backup/dump files.\n"
    "4. JS - js-endpoints on each bundle for hidden endpoints; scan-secrets on each bundle for leaked keys.\n"
    "5. UNAUTH - http-request each sensitive endpoint (you scan as an UNAUTHENTICATED user unless the operator "
    "gave you auth). Judge the response per VERIFY below.\n"
    "6. FUZZ - be THOROUGH; this is where SQLi/XSS/SSTI/LFI come from. Fuzz EVERY DISTINCT parameter-bearing "
    "endpoint you have seen - every `?param=` (id, q, category, email, url, name, search, slug, ...) AND id-like "
    "PATH segments (/product/1). Each PARAMETER is a SEPARATE injection surface and a single `fuzz <url>` only "
    "covers the params in THAT url - so fuzzing /search?q does NOT cover /product?id or /?category. Call fuzz "
    "ONCE PER distinct param-url (it auto-injects that url's query params + id path segments and self-confirms). "
    "Also fuzz the swagger --fuzzable variants and graphql-audit any GraphQL endpoint. Do NOT skip params to save "
    "steps - fuzz is a cheap tool call and injection findings are the highest-value ones you can report.\n"
    "7. REPORT.\n\n"

    "VERIFY BEFORE YOU REPORT - THIS IS THE MOST IMPORTANT RULE. A 200 is NOT proof. Many hosts (Cloudflare, an "
    "SPA/Next.js, a PHP front-controller) return 200 with the SAME page for EVERY path - so /.env, "
    "/.aws/credentials and /total-junk all look like they 'exist'. You are GIVEN a CATCH-ALL FINGERPRINT below "
    "(what a random nonexistent path returns). Before flagging ANY exposure:\n"
    "  - If the response matches the catch-all fingerprint (same status + similar size/body), it is the "
    "front-controller - DROP it. If unsure, http-request another random path yourself and compare.\n"
    "  - CONTENT-CHECK: the body must actually BE what you claim - a .env has KEY=VALUE lines; /actuator/env is "
    "JSON with propertySources; /.git/config has [core]; wp users is a JSON array of user objects; phpinfo says "
    "'PHP Version'; a backup.sql is SQL. An HTML app-shell served for /.env is NOT a finding.\n"
    "  - OMIT: 401/403; a redirect to login; an auth-rejection body ({\"error\":\"Unauthorized\"}, "
    "{\"authenticated\":false}); an empty/ping body ([], {}, {\"status\":\"ok\"}); and a login FORM (the panel "
    "exists but is gated -> at most a Suggestion).\n"
    "  - A sensitive endpoint returning REAL DATA (emails/PII, records, tokens) with no auth IS the finding.\n\n"

    "WHAT TO REPORT (and what NOT):\n"
    "  - Report ONLY High / Medium / Suggestion. High = exposed .git/.env/credentials/heapdump/backup, OR a "
    "response leaking PII/secrets/records, OR unauthenticated admin/data. Medium = an internal-only or info "
    "surface. Suggestion = a swagger/phpinfo page, a login form, a gated debug path, a reachable GraphQL "
    "endpoint.\n"
    "  - IGNORE, never mention: missing security headers, clickjacking, CORS wildcards, cookie flags, TLS/cipher "
    "nits, bare version banners. Noise here.\n"
    "  - REDACT every secret value - report the pattern name + location only, never the live key.\n"
    "  - fuzz and graphql-audit self-confirm; report their confirmed injections as findings.\n\n"

    "OUT OF SCOPE (do NOT test; list under 'NOT covered'): authenticated/OAuth/MFA flows, SSRF/CSRF/"
    "open-redirect, stateful multi-step logic (coupon/OTP/checkout abuse), and infra (ports, subdomain takeover, "
    "TLS).\n\n"

    "BE ECONOMICAL, BUT COMPLETE: never repeat a call; batch independent tool calls in one turn; don't re-probe "
    "or chase dead paths. Economical means not WASTING calls - it does NOT mean skipping the fuzz coverage in "
    "step 6. Before you write the report, make sure you have FUZZED every distinct parameter-bearing endpoint you "
    "found and audited any GraphQL endpoint - those are the findings a scanner alone would miss. Only then "
    "finish.\n\n"

    "FINISH: when done, reply with NO tool call and ONE fenced ```json block (nothing else) with EXACTLY these "
    "fields. BOB formats the report from this - so the report has the identical structure every single run; you "
    "supply the CONTENT, not the layout:\n"
    "```json\n"
    "{\n"
    '  "application": {"description":"<2-4 sentences: what the app/API does + its purpose, concrete not '
    'boilerplate>","stack":"<framework/lang | web server | CDN/WAF | notable libs>","api":"<REST / GraphQL / '
    'RPC / none>","auth":"<session cookie / JWT / OAuth / none observed>"},\n'
    '  "findings": [{"severity":"High|Medium|Suggestion","title":"<short>","url":"<url>","evidence":"<=100 '
    'chars, redacted>"}],\n'
    '  "attack_surface": ["<attacker-interesting endpoint> - <why>"],\n'
    '  "coverage": "<one line: what you actually checked>",\n'
    '  "bottom_line": "<one sentence: the single biggest problem, or nothing obviously exposed>"\n'
    "}\n```\n"
    "Only VERIFIED findings go in `findings` (High/Medium/Suggestion, per the rules above). If nothing survived "
    "verification, give an empty findings list and say so in bottom_line. Redact secret values.")


def _call(argv: list, headers: list, debug: bool = False) -> str:
    """Run a DEFINED boxcutter sub-command IN-PROCESS and return its raw stdout (the JSON envelope). A tool
    outside the allowlist is refused; header-capable tools get the operator's --header(s) appended; a missing
    binary / failure returns an error envelope, never raises."""
    if not argv or argv[0] not in _TOOLS:
        return json.dumps({"success": False, "error": f"{argv[0] if argv else '?'} is not a defined bob tool"})
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


def _catch_all_fingerprint(base_url: str, headers: list, debug: bool) -> str:
    """Hand the model EVIDENCE (not an enforced gate): what a definitely-nonexistent path returns here. On a
    catch-all/CDN/SPA host this is a 200 shell, so the model knows a matching 'finding' is a false positive."""
    lines = []
    for _ in range(2):
        rp = base_url.rstrip("/") + "/zzq-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        try:
            d = (json.loads(_call(["http-request", rp], headers, debug)).get("data") or [{}])[0]
            lines.append(f"  {rp} -> status {d.get('status')}, {len(d.get('content') or '')} bytes, "
                         f"title {str(d.get('title') or '')[:40]!r}")
        except Exception:  # noqa: BLE001
            lines.append(f"  {rp} -> (no response)")
    return ("CATCH-ALL FINGERPRINT (a random nonexistent path returns this - a 'finding' that matches it is a "
            "front-controller FALSE POSITIVE, drop it):\n" + "\n".join(lines))


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "suggestion": 4, "info": 5}


def _summarize(host: str, findings: list) -> tuple:
    """A DETERMINISTIC, notification-ready summary from the final findings. Returns (notification_line,
    markdown_block, structured_dict) - a one-liner you can drop straight into Slack/email, a `### Summary` block
    for the report, and machine fields for the envelope."""
    counts: dict = {}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        counts[s] = counts.get(s, 0) + 1
    high = counts.get("critical", 0) + counts.get("high", 0)
    med = counts.get("medium", 0)
    sug = counts.get("suggestion", 0) + counts.get("low", 0) + counts.get("info", 0)
    verdict = ("CRITICAL EXPOSURE" if high else "ISSUES FOUND" if med
               else "MINOR / REVIEW" if sug else "NOTHING EXPOSED")
    top = [str(f.get("title", "")).strip()
           for f in sorted(findings, key=lambda f: _SEV_RANK.get(str(f.get("severity", "info")).lower(), 9))
           if str(f.get("title", "")).strip()][:3]
    notif = f"[bob] {verdict} | {host} | {high} High, {med} Medium, {sug} Suggestion"
    if top:
        notif += " | top: " + "; ".join(top[:2])
    md = ["### Summary", notif]
    if top:
        md += [""] + [f"- {t}" for t in top]
    data = {"verdict": verdict, "high": high, "medium": med, "suggestion": sug,
            "counts": counts, "top": top, "notification": notif}
    return notif, "\n".join(md), data


def _parse_output(text: str) -> tuple:
    """The agent emits a structured json (application / findings / attack_surface / coverage / bottom_line). Pull
    it out; bob renders the report from it so the LAYOUT is bob's, not the model's. Returns (data, findings)."""
    obj = extract_json(text)
    if not isinstance(obj, dict):
        obj = {}
    findings = [f for f in (obj.get("findings") or []) if isinstance(f, dict)]
    return obj, findings


def _render_report(target: str, data: dict, findings: list, summary_md: str) -> str:
    """Render the report from structured data with a fixed layout. Sections keep the same order and format every
    run, but a CONTENT section with nothing in it (no High exposure, no findings, no attack surface) is DROPPED
    rather than shown with a 'None' placeholder - a clean scan gets a clean, short report. The always-relevant
    sections (Summary, Application, Coverage, Bottom line) are always present."""
    app = data.get("application") if isinstance(data.get("application"), dict) else {}
    srt = sorted(findings, key=lambda f: _SEV_RANK.get(str(f.get("severity", "info")).lower(), 9))
    highs = [f for f in srt if str(f.get("severity", "")).lower() in ("critical", "high")]
    surf = [str(s).strip() for s in (data.get("attack_surface") or []) if str(s).strip()]

    out = [f"## Bob - surface scan: {target}", "", summary_md, "",
           "### Application", str(app.get("description") or "(not determined)").strip(),
           f"**Stack:** {app.get('stack') or 'unknown'}  |  **API:** {app.get('api') or 'unknown'}  |  "
           f"**Auth:** {app.get('auth') or 'not observed'}"]
    if highs:                                        # only when there's something critical to highlight
        out += ["", "### Exposed / problematic (fix or confirm intended)"]
        out += [f"- **[{str(f.get('severity', 'High')).title()}]** {str(f.get('title', '')).strip()} - "
                f"`{f.get('url', '')}`" + (f" - {str(f.get('evidence', '')).strip()}" if f.get("evidence") else "")
                for f in highs]
    if srt:                                          # only when there are findings at all
        out += ["", "### Findings", "| Severity | Finding | Location |", "| --- | --- | --- |"]
        out += [f"| {str(f.get('severity', 'info')).title()} | {str(f.get('title', '')).strip()} | "
                f"`{f.get('url', '')}` |" for f in srt]
    if surf:                                         # only when the agent noted attacker-interesting surface
        out += ["", "### Attack surface worth a look"] + [f"- {s}" for s in surf]
    out += ["", "### Coverage", str(data.get("coverage") or "(not stated)").strip(),
            "**NOT covered** (route to appsec): authenticated/OAuth/MFA flows, SSRF/CSRF/open-redirect, stateful "
            "multi-step logic, and infra (ports, subdomain takeover, TLS).", "",
            f"**Bottom line:** {str(data.get('bottom_line') or 'no summary provided').strip()}"]
    return "\n".join(out)


# -- fuzz backstop: guarantee EVERY param-bearing endpoint gets fuzzed, whatever the agent chose ------------
_ID_SEG = re.compile(r"\A(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{32,})\Z")


def _data(raw: str) -> list:
    try:
        e = json.loads(raw)
        return e.get("data") or [] if isinstance(e, dict) else []
    except Exception:  # noqa: BLE001
        return []


def _in_scope(url: str, host: str) -> bool:
    h = (urlparse(url).hostname or "").lower()
    return bool(h) and (h == host or h.endswith("." + host))


def _param_bearing(url: str) -> bool:
    """A URL worth fuzzing: it carries a query string, or an id-like path segment (/product/1)."""
    p = urlparse(url)
    return bool(p.query) or any(_ID_SEG.match(s) for s in p.path.split("/") if s)


def _fam(url: str) -> str:
    """Injection-surface identity: host + path (id segments folded to {id}) + the set of param NAMES - so
    /product?id=1 and /product?id=2 fuzz once, but /product?id and /search?q stay distinct."""
    p = urlparse(url)
    segs = ["{id}" if _ID_SEG.match(s) else s.lower() for s in p.path.strip("/").split("/") if s]
    names = sorted({q.split("=", 1)[0] for q in (p.query or "").split("&") if q})
    return f"{(p.hostname or '').lower()}/{'/'.join(segs)}?{','.join(names)}"


def _urls_in(raw: str) -> list:
    """URL strings inside a tool envelope's data - items that are strings, dicts with a `url`, or js-endpoints'
    nested `endpoints`. This is how bob recovers every param URL the agent's crawl/probe surfaced."""
    out = []
    for d in _data(raw):
        if isinstance(d, str) and d.startswith(("http://", "https://")):
            out.append(d)
        elif isinstance(d, dict):
            u = d.get("url")
            if isinstance(u, str) and u.startswith(("http://", "https://")):
                out.append(u)
            for e in d.get("endpoints") or []:
                eu = e.get("url") if isinstance(e, dict) else e
                if isinstance(eu, str) and eu.startswith(("http://", "https://")):
                    out.append(eu)
    return out


def _norm_scheme(url: str, scheme: str, host: str) -> str:
    p = urlparse(url)
    if (p.hostname or "").lower() == host:
        return urlunparse((scheme, p.netloc, p.path or "/", p.params, p.query, ""))
    return url


def _fuzz_backstop(base_url: str, host: str, headers: list, cache: dict, args) -> tuple:
    """After the agent finishes, DETERMINISTICALLY fuzz every distinct param-bearing endpoint it discovered but
    did not fuzz itself. Sources: every URL the agent http-requested + every URL inside a tool result (katana,
    swagger-endpoints, js-endpoints, ...). Deduped by injection-surface family, capped, http->base scheme.
    Returns (fuzz_findings, endpoints_fuzzed, capped)."""
    base_scheme = urlparse(base_url).scheme or "https"
    discovered: set = set()
    fuzzed_fams: set = set()
    for k, out in cache.items():
        tool = k[0] if k else ""
        if tool == "fuzz" and len(k) > 1:
            fuzzed_fams.add(_fam(k[1]))              # the agent already fuzzed this family - don't redo it
        if tool == "http-request" and len(k) > 1:
            discovered.add(k[1])
        discovered.update(_urls_in(out))

    targets: dict = {}
    for u in discovered:
        if not _in_scope(u, host) or not _param_bearing(u):
            continue
        fam = _fam(u)
        if fam in fuzzed_fams or fam in targets:
            continue
        targets[fam] = _norm_scheme(u, base_scheme, host)

    ordered = list(targets.values())
    cap = max(1, args.fuzz_cap)
    capped = len(ordered) > cap
    findings: list = []
    for u in ordered[:cap]:
        debug_print("bob[backstop]> boxcutter fuzz " + u)
        findings += [f for f in _data(_call(["fuzz", u, "--timeout", str(args.fuzz_timeout)], headers, args.debug))
                     if isinstance(f, dict)]
    return findings, min(len(ordered), cap), capped


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL / host (the app root)")
    parser.add_argument("--fuzz-cap", dest="fuzz_cap", type=int, default=20,
                        help="Backstop: max distinct param endpoints to auto-fuzz after the agent finishes "
                             "(0 disables the backstop). Guarantees every param is fuzzed, not just the ones "
                             "the agent chose")
    parser.add_argument("--fuzz-timeout", dest="fuzz_timeout", type=int, default=45,
                        help="Per-endpoint budget (seconds) for each backstop fuzz call")
    add_agent_args(parser, max_steps=30, budget=600)


def run(args) -> int:
    target = args.target.strip()
    if not target:
        output_result([], args.output, "a target is required")
        return 2
    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    host = (urlparse(base_url).hostname or "").lower()

    provider_cls = PROVIDERS[args.provider]          # bob is an LLM agent - a provider/key is MANDATORY
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"bob: an LLM is required - provide --api-key or set {provider_cls.env} "
                         f"for --provider {args.provider}\n")
        return 2
    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)

    headers = list(args.header or [])                # sent on every tool call (auth for a login-walled app)
    if args.context.strip():
        cfg = briefing.parse(provider, args.context, host)
        headers += cfg.get("headers", []) or []
        if cfg.get("headers"):
            sys.stderr.write("bob :: auth header(s) parsed from --context (values hidden)\n")

    tools_spec = toolschema.native_tools(_TOOLS)
    debug_print(f"bob :: fingerprinting the catch-all for {base_url} ...")
    fingerprint = _catch_all_fingerprint(base_url, headers, args.debug)
    user = (f"TARGET: {base_url}\nSCOPE: the host {host} only.\n\n{fingerprint}\n\n"
            "Run your short surface scan now - drive the tools, verify before you flag, and finish with the "
            "report. Begin.")
    messages = [{"role": "user", "content": user}]

    cache: dict = {}
    count: dict = {}
    final_text = ""
    nudged = False
    deadline = time.time() + max(30, args.budget)

    for step in range(max(1, args.max_steps)):
        overtime = time.time() > deadline
        try:
            resp = provider.send(_SYSTEM, messages, tools_spec)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"bob: provider error: {exc}\n")
            break
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        if text.strip():
            final_text = text
            debug_print("bob> " + (" ".join(text.split()) if args.debug else " ".join(text.split())[:220]))
        if not calls:
            if final_text.strip() and any(m in final_text for m in ("```json", '"application"', '"findings"')):
                break                                # the agent delivered the structured output
            if not nudged:                           # a chatty turn without acting - push it once
                nudged = True
                messages.append({"role": "user", "content": "Use the tools to actually scan - start with "
                                 "http-request on the base and go from there. Do not answer without acting."})
                continue
            break
        if overtime:                                 # out of budget: ask for the report instead of more tools
            messages.append({"role": "user", "content": "Wall-clock budget reached. Stop scanning and write the "
                             "FINAL report now (markdown + the json block), from what you already have."})
            continue
        results = []
        for c in calls:
            if c["name"] not in _TOOLS:
                results.append({"id": c["id"], "output": json.dumps({"error": f"{c['name']} is not a bob tool"})})
                continue
            argv = toolschema.to_argv(c["name"], c["args"])
            keyt = tuple(argv)
            count[keyt] = count.get(keyt, 0) + 1
            if count[keyt] > 2:
                out = json.dumps({"success": False, "error": "already ran this exact call - reuse the result"})
            elif keyt in cache:
                out = cache[keyt]
            else:
                debug_print("bob> boxcutter " + " ".join(str(a) for a in argv))
                out = _call(argv, headers, args.debug)
                cache[keyt] = out
            results.append({"id": c["id"], "output": _cap(out)})
        messages += provider.tool_results(results)

    data, findings = _parse_output(final_text)       # structured output; bob renders the report from it
    for f in findings:                               # normalise severity casing for the envelope's sort/dedup
        f["severity"] = str(f.get("severity", "info")).lower()

    # FUZZ BACKSTOP: deterministically fuzz every param-bearing endpoint the agent discovered but skipped, so no
    # parameter goes untested regardless of the model's choices. Its findings join the same findings list, so the
    # fixed-template render below includes them automatically.
    if args.fuzz_cap > 0:
        bf, n_fuzzed, capped = _fuzz_backstop(base_url, host, headers, cache, args)
        debug_print(f"bob :: [backstop] auto-fuzzed {n_fuzzed} param endpoint(s) the agent skipped"
                    + (" (capped - raise --fuzz-cap for more)" if capped else "")
                    + f"; {len(bf)} injection finding(s)")
        for f in bf:
            f["severity"] = str(f.get("severity", "info")).lower()
        findings += bf

    # DETERMINISTIC summary (notification-ready) + FIXED-structure report (identical layout every run)
    notif, summary_md, summary = _summarize(host, findings)
    report = _render_report(base_url, data, findings, summary_md)

    debug_print(f"\nbob :: {notif}  ({step + 1} steps)\n")
    debug_print(report + "\n")

    if getattr(args, "report", None):
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
            debug_print(f"bob :: report written to {args.report}")
        except OSError as exc:
            sys.stderr.write(f"bob: could not write report to {args.report}: {exc}\n")

    extra = {"target": base_url, "report": report, "summary": summary, "notification": notif, "steps": step + 1}
    if getattr(args, "table", False) and not args.output:
        sys.stdout.write(report + "\n")
    else:
        output_result(findings, args.output, extra=extra)
    return 0

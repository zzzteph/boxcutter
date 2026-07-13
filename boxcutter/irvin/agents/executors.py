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
from .base import Executor, say

# Shared by EVERY browser-driving agent (spa, explore, auth, visor): HOW to build a click / enter-data flow by
# COORDINATES when CSS selectors can't drive the page. Appended to each such objective so they all work an SPA
# the same way - see the page, read coordinates off the grid, confirm, act, re-read.
_CLICK_FLOW = (
    "\nBUILDING A CLICK / ENTER-DATA FLOW BY COORDINATES (visual-driver). When a control can't be driven by a "
    "CSS selector - an obfuscated CSS-in-JS theme, a canvas / JS-rendered widget, or a flow that only lets a "
    "HUMAN through a bot check - drive the page by SCREEN COORDINATES with `visual-driver`: real curved, eased "
    "mouse motion and per-key typing, all trusted events, the way a person actually uses the page. It holds a "
    "PERSISTENT session and each call returns a screenshot with a coordinate GRID (x across the top, y down the "
    "left, labeled every 100px).\n"
    "THE RHYTHM - one interaction at a time: `wait` for the page to settle -> `screen` to SEE it -> READ the "
    "target's x,y off the grid -> `probe:X,Y` to CONFIRM what is there (it reports e.g. `input [password]`, "
    "`button \"Log In\"`) -> act -> `wait` -> `screen` again to see the RESULT, then decide the next "
    "coordinate. Act with: `click:X,Y` a field/button, `put:TEXT` to type into the focused field (for a "
    "credential put the __USER_x__/__PASS_x__ token, NEVER a real value), `key:Enter`/`key:Tab`, `clear` to "
    "empty a field, `drag:X1,Y1->X2,Y2` for a slider, `move:X,Y` to hover before a click. THE SCREENSHOT IS "
    "YOUR SOURCE OF TRUTH - two ways to aim: (1) READ the target's x,y straight off the grid and `click:X,Y` / "
    "`put` there - this is the PRIMARY, reliable method and it works even when the DOM is hidden (a widget / "
    "shadow-DOM / iframe / canvas login the selectors can't reach), exactly how a human clicks. (2) "
    "`click_text:Log in` / `fill_text:email=...` LOCATE a control by its text/name and act on it - a handy "
    "shortcut WHEN the element is a plain DOM node, but if `find`/`fill_text` returns 'not found' or hits the "
    "wrong thing (common for the login FIELDS in an SPA modal), DON'T get stuck: read the coordinate off the "
    "screenshot and `click:X,Y` it. Guessing pixels WITHOUT looking is what fails; READING the exact coordinate "
    "off the gridded screenshot is reliable - do that. Only chain actions "
    "that stay on the SAME screen; after ANYTHING that navigates or reflows (a click that opens a form, a "
    "submit), take a NEW `screen` before aiming again - your coordinates came from the LAST screenshot, and the "
    "page often re-renders elements to new positions.\n"
    "FIRST dismiss any cookie / consent / age overlay (`click_text:Accept all` or probe+click its button) - it "
    "sits on top and blocks every click underneath. A LOGIN then looks like: `click_text:Log in` - and make "
    "SURE it is LOG IN / SIGN IN, NOT 'Sign up' / 'Create account' / 'Register' (those lead to the WRONG page); "
    "if you land on a registration/create-account page, `find:Log in` or `click_text:Already have an account` to "
    "get back to login -> wait -> screen -> (choose the email/password method if the page also offers social "
    "logins, e.g. `click_text:Continue with email`) -> READ the EMAIL field's x,y off the grid and `click:X,Y` "
    "then `put:__USER_x__` (or `fill_text:email=__USER_x__` if the field is a plain DOM node) -> the SAME for "
    "the PASSWORD field with __PASS_x__ -> submit with `key:Enter` or click the submit button -> wait -> screen "
    "to CONFIRM "
    "you reached the logged-in app (not still the form, not a signup page).\n"
    "CAPTCHA - recognise it and handle it, don't give up: a reCAPTCHA \"I'm not a robot\" CHECKBOX renders in "
    "an iframe the DOM can't touch, but you CAN click it BY COORDINATE - read its box off the screenshot and "
    "click it with human motion, wait, screen (it often passes). If an image challenge ('select all traffic "
    "lights...') appears, read the tiles and click the matching ones by coordinate as a best-effort, then "
    "verify/submit; if it just loops, say so in artifacts.notes. For an INVISIBLE / score-based check (a small "
    "reCAPTCHA badge bottom-right, or a 'verify you are human' wall with nothing to click), do a `captcha` "
    "idle-mouse warm-up BEFORE you submit to raise your score - and a short `captcha` before the final submit "
    "is good practice regardless. Correct your aim from each screenshot; probe a field before typing so text "
    "never lands in nothing.")


def _visual_rewrite(sid: str, ctx, args: dict) -> dict:
    """Pin a visual-driver call to a persistent session and substitute the secret typing tokens
    (__USER_x__/__PASS_x__) with the real values - AT DISPATCH, so the model never sees the session id or the
    credential. Shared by every browser agent's _rewrite_call."""
    new = {**args, "session": sid}
    if args.get("action"):
        new["action"] = [ctx.resolve_secret_tokens(a) for a in args["action"]]
    return new


class BrowserExecutor(Executor):
    """Base for executors that drive a real browser. Gives each its own PERSISTENT session id (used by the
    visual-driver coordinate flow), tears it down when the commission ends, and routes visual-driver calls
    through the shared session-pin + secret-token substitution. Subclasses add their own tools/objective and
    may EXTEND _rewrite_call via super() (e.g. auth also swaps a browser-login placeholder; explore also
    attaches an identity header to browser-actions)."""
    def __init__(self):
        self._sid = f"{self.name}-{uuid.uuid4().hex[:8]}"

    def _rewrite_call(self, ctx, name: str, args: dict) -> dict:
        if name == "visual-driver":
            return _visual_rewrite(self._sid, ctx, args)
        return args

    def run(self, ctx, step, runner, provider) -> dict:
        from ...core.cdp import close_session
        try:
            return super().run(ctx, step, runner, provider)
        finally:
            close_session(self._sid)                       # persistent browser session lives only per commission


class Recon(Executor):
    name = "recon"
    description = "Reconnaissance: linked/spec/JS surface + sibling hosts, with method+params+auth, deduped and existence-gated."
    tools = {"httpx", "http-request", "katana-crawl", "js-endpoints", "swagger-specs",
             "swagger-endpoints", "graphql-detect", "dnsx"}
    verify_paths_exist = True       # the agentic existence gate is the authoritative liveness check at handoff
    max_steps = 16
    objective = (
        "You are a RECONNAISSANCE specialist - your deliverable is the target's LINKED, spec-derived and "
        "JS-derived attack surface PLUS the sibling hosts the app really uses, never an invented one (unlinked "
        "brute paths are dirbust's lane). Enumerate authoritatively: an OpenAPI/GraphQL schema is usually the "
        "whole API (swagger-endpoints --fuzzable). Surface the sibling/backend hosts the app ITSELF reveals - a "
        "host in a link, an absolute API base URL in its JS, a config value - and confirm they resolve / are "
        "live with `dnsx` and `httpx` - an api.* or backend host is prime "
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


class Spa(BrowserExecutor):
    name = "spa"
    description = "SPA/JS rendering: drive a headless browser to capture the real (often cross-origin) API a single-page app calls."
    tools = {"browser-crawl", "visual-driver", "http-request"}
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
        "client-side surface. If the auto-crawl can't trigger the API because the page needs a human action "
        "first (enter an address, dismiss a modal, click a control), build that interaction as a coordinate "
        "flow with visual-driver to reach the real surface." + _CLICK_FLOW)


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
        "positive (it exists and is protected). RECURSE into every directory you surface: dirb/dirsearch are NOT "
        "recursive, so when a hit is itself a DIRECTORY (a trailing-slash 200 or a served index, e.g. /admin/ or "
        "/admin/panel/), you MUST run dirsearch/dirb AGAIN with that directory as the base before you finish - a "
        "login panel or app directory like /admin/panel/ almost always hides config/backup/.git/login scripts "
        "one level deeper. Descend into each NEW directory you find (a few levels deep) until no new directory "
        "appears; NEVER hand back a discovered directory you have not yourself searched inside. Judge against "
        "YOUR measured baseline, not a fixed count. NON-GOAL: do "
        "NOT nuclei-scan, dump .git, or judge sensitivity (exposure/git-dumper/secrets lanes) - you prove "
        "existence and classify. Emit each kept path as url + status + size + a one-word class "
        "(panel/config/backup/debug/api) in artifacts.endpoints, with a raw->kept count. When a hit is a "
        "PANEL/admin/login/privileged interface, ALSO raise a panel lead (artifacts.leads, cls=panel, url=the "
        "panel) so EXPOSURE is commissioned to report the reachable admin interface - a discovered admin panel "
        "must never be left as just an endpoint.")


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
        "- BFLA: a low-privilege OR unauth identity invoking a privileged operation that succeeds = finding. An "
        "EXPOSED admin/privileged panel or endpoint (e.g. /admin) reachable without the required role is BFLA - "
        "prove its privileged FUNCTIONALITY actually works (load admin data, submit an admin action), not merely "
        "that the page returns 200.\n"
        "STAY IN YOUR LANE: you probe ACCESS, not other vuln classes. If a parameter throws a SQL error / DB "
        "stack trace, looks like file inclusion, or reflects your input, that is NOT your finding - RAISE it in "
        "artifacts.leads (cls=sqli/lfi/xss with the url, param, and the exact error) so the owning specialist is "
        "commissioned; do not fuzz or exploit it yourself.\n"
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
        "Drive `fuzz` against every query parameter and id-like path segment - it carries a comprehensive "
        "built-in payload DATABASE covering every class below (baseline-diffed, reliability-reconfirmed), so you "
        "just point {FUZZ} at the input and run it plain (there is no payload option, and you don't need one - "
        "the battery is broader than any hand-picked list). To probe ONE specific custom payload at an exact "
        "injection point, use http-request instead of fuzz. Reason from a class-specific differential, not a "
        "bare status:\n"
        "- SQLi -> a SQL error string or a deterministic boolean/time oracle (escalate to the sqli specialist).\n"
        "- XSS -> a marker reflected UNESCAPED in its context (escalate to xss).\n"
        "- LFI/path-traversal -> a traversal/wrapper signal (escalate to path-traversal).\n"
        "- SSTI -> template math actually evaluated.\n"
        "ERROR-BASED TELL IS DECISIVE: a DB error or framework STACK TRACE in ANY response body - PDOException, "
        "'SQL syntax'/SQLSTATE, 'Warning: mysql_*', 'ORA-#####', or a trace leaking a source path like "
        "'/app/index.php:53' - CONFIRMS injection on its own (cls=sqli, or the matching class). File it EVEN IF "
        "`fuzz` reports 'no differential': the differential can miss an error page that looks similar. Do NOT "
        "trust the fuzz verdict alone - fetch a couple of candidates with http-request and READ the body for "
        "these signatures before you conclude an input is clean.\n"
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
        "You are a CROSS-SITE-SCRIPTING specialist (A03). Fire `fuzz` PLAIN against the injectable parameter - "
        "its built-in payload DATABASE already carries the XSS battery (baseline-diffed, reliability-"
        "reconfirmed), so you just point {FUZZ} at the input and run it; there is NO --payload option and you "
        "don't need one. fuzz flags which inputs reflect; then PROVE execution with `http-request`: re-issue the "
        "reflecting payload and READ the response - http-request hands back the FULL body plus status/headers, "
        "so it IS your grep surface. Put a unique canary marker in a payload (e.g. xY9zCANARY) so you can find "
        "it unambiguously in the body and tell a real break-out from an escaped echo. To try ONE specific "
        "context-crafted break-out the battery doesn't cover (a JS-string context, an attribute break-out), send "
        "that exact payload with http-request. Distinguish reflected (echoed into the immediate response), "
        "stored (injected on one endpoint, surfacing on another - re-fetch the rendering view), and DOM-driven. "
        "PROOF is the marker appearing UNESCAPED in an executing context - a reflection that stays HTML-entity-"
        "encoded (&lt;) or inert is NOT a finding. Re-issue to prove it reproduces; report with the verbatim "
        "payload, the rendering URL, and cls=xss.")


class PathTraversal(Executor):
    name = "path-traversal"
    description = "LFI / path traversal (A03/A05): prove you can read a file you should not; the sole owner of generic '../'."
    tools = {"fuzz", "http-request"}
    max_steps = 12
    objective = (
        "You are an LFI / PATH-TRAVERSAL specialist and the SOLE owner of generic '../' file traversal "
        "(object-reference id swapping is access-control's lane). Fire `fuzz` PLAIN against file/path/include "
        "parameters - its built-in payload DATABASE already carries the traversal/LFI battery (../ at depth, "
        "URL/double-encoding, null/extension tricks, PHP wrappers), so just point {FUZZ} at the input and run "
        "it; there is NO --payload option. fuzz flags which inputs bite; then PROVE the read with `http-request`: "
        "re-issue the payload and READ the response - http-request hands back the FULL body, so it IS your grep "
        "surface for the leaked content. For a specific target the battery doesn't cover (the app's own source "
        "via php://filter/convert.base64-encode/resource=<path>, a particular config file), send that exact "
        "payload with http-request. Likely targets: /etc/passwd, app source, framework config (.env, web.config, "
        "config.php, appsettings.json). PROOF is the leaked file CONTENT quoted (redacted) - a root:x:0:0 line, "
        "a connection string, a key, or the base64 you decode - never a bare 200 or a soft-404. Re-issue to "
        "confirm reproduction; report with the verbatim payload, the read path, and cls=lfi.")


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
        "git-extract against a tarpit. Check /.git/ NOT ONLY at the web root but UNDER each discovered app "
        "directory the brief points you at (e.g. /admin/.git/, /app/.git/) - a repository is frequently exposed "
        "ONE DIRECTORY DEEP, not at the root; probe <dir>/.git/HEAD and <dir>/.git/config there too, and if it "
        "is real, run git-extract against that <dir>/.git/. Then run git-extract to reconstruct the working tree "
        "and scan-secrets over "
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
        "false-positives.\n"
        "EXPOSED ADMIN/MANAGEMENT PANEL is YOURS to own end to end (a `panel` lead is routed to you): an "
        "admin/management interface reachable from outside is a finding. Fetch it and judge from the response - "
        "a login-GATED panel is a Low (attack-surface) finding; one whose console/actions/data load WITHOUT "
        "login is High (an unauthenticated console). Report it directly with the redacted evidence; do NOT hand "
        "it off to another lane.")


class Auth(BrowserExecutor):
    name = "auth"
    description = ("Session management: establish OR re-establish a login session for one identity (the "
                   "first login before round 1, and any mid-run refresh, both go through here). Escalates "
                   "simple form -> browser-actions describe+screenshot -> a VISUAL coordinate login (human "
                   "mouse motion) when selectors can't cope. The DECISION to (re-)auth is the agent's "
                   "(auth-profile weighs the auth-signal evidence for a refresh; the pipeline always "
                   "bootstraps the first one); the CREDENTIAL never reaches the model - only a placeholder does.")
    tools = {"browser-login", "browser-actions", "visual-driver", "http-request"}
    cost = "low"        # one login flow, not a battery of calls
    max_steps = 16      # room for the visual coordinate fallback (screenshot -> click -> screenshot -> fill ...)
    objective = (
        "You are the SESSION/AUTH specialist - your ONLY job is getting ONE identity an ACTIVE login session, "
        "whether this is its first login or a refresh of one that went stale. RELEVANT CONTEXT below names the "
        "identity and a stored-credential PLACEHOLDER token - never the real password: you never see or need "
        "it, it is substituted right before a call actually dispatches, so never alter, guess, or invent a "
        "credential value of your own.\n"
        "ONE CARVED-OUT EXCEPTION - WEAK/DEFAULT-CREDENTIAL CHECK: when RELEVANT CONTEXT explicitly asks you to "
        "check an exposed admin/login panel for weak credentials AND no real credential is supplied for it, you "
        "MAY try a SMALL FIXED set of well-known PUBLIC defaults (admin/admin, admin/password, "
        "administrator/administrator, root/root, root/toor - a handful, NEVER a brute-force, nothing that could "
        "lock an account). These are public defaults, not a secret you are inventing. If one logs in, that is a "
        "WEAK/DEFAULT CREDENTIALS finding (High): file it (cls=weak-creds) with the working pair redacted and "
        "keep the session. If none of the handful work, stop and report none - do not keep guessing.\n"
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
        "GO VISUAL - MANDATORY before you may EVER report a login failure. The MOMENT browser-login and "
        "browser-actions describe can't SURFACE or complete the login - the fields never appear, describe lists "
        "only marketing/landing elements, clicking the account/'Log In' control doesn't expose inputs, or the "
        "form is a JS / shadow-DOM / iframe / canvas / obfuscated widget the DOM can't reach - that is EXACTLY "
        "the trigger to switch to `visual-driver`, NOT a reason to give up. (browser-actions screenshot gives "
        "you EYES but you still act via SELECTORS; visual-driver lets you ACT on what you SEE, by coordinate, "
        "like a human - that is the whole point.) EXPLORE BEFORE YOU ACT: first screenshot the page and MAP the "
        "login flow with `find`/`probe` - locate the 'Log in' control (find:Log in), open it, screenshot the "
        "modal, then READ off the gridded screenshot where the email-method option, the EMAIL field, the "
        "PASSWORD field and the SUBMIT button are, so you KNOW where each is BEFORE you act. THEN execute "
        "deliberately: `click_text:Log in` (the LOGIN control, NOT Sign up / Create account) - or click it at "
        "the x,y you read off the grid; `click_text:Log in with Email` if a method chooser appears; then fill "
        "the fields BY COORDINATE read off the grid - `click:X,Y` the EMAIL field then `put:__USER_x__`, "
        "`click:X,Y` the PASSWORD field then `put:__PASS_x__` (coordinates are the RELIABLE path in an SPA "
        "modal; `fill_text:email/password` is only a shortcut when the field is a plain DOM node and often "
        "won't find a widget field) - then `key:Enter` to submit. See BUILDING A CLICK/ENTER-DATA FLOW below. "
        "Type the __USER_x__/__PASS_x__ tokens VERBATIM (RELEVANT CONTEXT names the exact ones) - substituted "
        "with the real credential privately at dispatch, like the placeholder.\n"
        "PROVE YOU ARE AUTHENTICATED before you store anything or claim success - a bag of pre-login / "
        "analytics / consent cookies is NOT a session, and a false 'session established' is WORSE than an "
        "honest failure (it makes the whole run test as authenticated when it isn't). This is almost certainly "
        "an SPA where the FRONTEND loads WITHOUT auth (the marketing/landing shell) but the BACKEND API is "
        "fully authed - so DO NOT judge success by the frontend looking logged in; judge it by the BACKEND. "
        "Confirm REAL authentication with an authenticated API call: use the `requests` view / flows to find a "
        "call (a /me, /account, /profile, /orders, /customer... endpoint, often on a DIFFERENT api.* host that "
        "may need --scope) that returns 200 with YOUR user data, not a 401 or a redirect to login.\n"
        "STORE THE RIGHT SESSION ARTIFACT: for a token/SPA app the session is usually a JWT the app sends as "
        "`Authorization: Bearer <jwt>` to that API - you'll see it as `req_auth` on the authenticated flow; put "
        "THAT exact header in artifacts.tokens. For a cookie app, store `Cookie: <the session cookies>` "
        "instead. Whichever header the authenticated API call used to get YOUR data IS the session. Set "
        "\"label\" to the identity (e.g. \"A\") so it REPLACES any stale one. If you clicked a SOCIAL login "
        "(Google/Facebook/Apple) you cannot complete, or you never see an authed API call succeed, that is a "
        "FAILURE: say so plainly in artifacts.notes and store NOTHING. Report FAILURE only after the "
        "visual-driver coordinate flow has GENUINELY been tried and still couldn't reach a PROVEN login (wrong "
        "creds, MFA/captcha, social-only) - a failure reported without trying visual-driver, or a 'success' you "
        "did not PROVE against the backend, are both unacceptable." + _CLICK_FLOW)

    def run(self, ctx, step, runner, provider) -> dict:
        """ADAPTER: log in with the standalone logio ENGINE (staged / probe-before-type / landed-verified) and
        hand the identity back as a token, so IRVIN's auth desk uses the same proven login as `boxcutter ai
        logio`. Falls back to the built-in browser-login / visual escalation (super().run) whenever logio
        errors or can't authenticate - so this can only ADD reliability, never remove it. NB: logio drives its
        own visual-driver dispatch (not the scoped Runner), which is correct for a login that must reach the
        app's own login / SSO host."""
        label = self._resolve_label(ctx, step)
        placeholder = ctx.placeholder_for(label)
        creds = ctx.creds_for_placeholder(placeholder) if placeholder else ""
        if not creds or ":" not in creds:
            return super().run(ctx, step, runner, provider)        # no usable credential -> base handles/reports
        user, _, pw = creds.partition(":")
        subs = {"__USER__": user, "__PASS__": pw, "__CREDS__": creds}
        target = ctx.creds_login_url(label) or ctx.base_url
        headers = list(getattr(runner, "global_headers", []) or [])
        try:
            from ...ai.logio import login as logio_login
            say(f"irvin:{self.name}", f"logio: staged login for identity {label} at {target}")
            res = logio_login(provider, target, subs, grid=25, trace=None, headers=headers, max_steps=14)
        except Exception as exc:  # noqa: BLE001
            say(f"irvin:{self.name}", f"logio errored ({exc}); falling back to the built-in login")
            return super().run(ctx, step, runner, provider)
        if res.get("authenticated") and res.get("session_header"):
            say(f"irvin:{self.name}", f"logio authenticated identity {label}")
            return {"findings": [], "verification": {},
                    "artifacts": {"tokens": [{"label": label, "header": res["session_header"], "source": "logio"}],
                                  "notes": [f"logio staged login established a session for identity {label}"]}}
        say(f"irvin:{self.name}", f"logio did not authenticate {label} (stopped at "
                                  f"{res.get('failed_stage')}); falling back to the built-in login")
        return super().run(ctx, step, runner, provider)

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
        u_tok, p_tok = ctx.secret_tokens(label)
        vis = (f" If you fall back to the visual-driver (coordinate login), type the username as {u_tok} and "
               f"the password as {p_tok} (substituted privately, same as the placeholder).")
        login_url = ctx.creds_login_url(label)
        if login_url:
            return {**step, "args": {"target": login_url, "creds": placeholder},
                    "context": (f"Identity {label} needs an active session. Start with browser-login using "
                               f"target={login_url!r} and creds={placeholder!r} EXACTLY as shown (a safe "
                               "reference token, not a real password). On success, set artifacts.tokens[0].label "
                               f"to {label!r}." + vis)}
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
                           f"submitting, then log in and set artifacts.tokens[0].label to {label!r}." + vis)}

    def _rewrite_call(self, ctx, name: str, args: dict) -> dict:
        if name == "browser-login" and isinstance(args.get("creds"), str):
            real = ctx.creds_for_placeholder(args["creds"])
            return {**args, "creds": real} if real else args
        return super()._rewrite_call(ctx, name, args)      # visual-driver: session pin + secret-token substitution


class Explorer(BrowserExecutor):
    name = "explore"
    description = ("Human-like SPA exploration: drive a PERSISTENT, already-logged-in browser session, click "
                   "through the real UI, and read the full request/response traffic to map the TRUE "
                   "authenticated API surface the static crawlers never see.")
    tools = {"browser-actions", "visual-driver", "http-request"}
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
        "endpoint is real (the browser genuinely called it - it is) and hand back FACTS. Use the `requests` "
        "action for a PROXY-LIKE view of every host/endpoint the page talks to (not just what your clicks "
        "triggered) - `requests` for the host map, `requests:<host>` to list one - and add the real backend "
        "API hosts you find to artifacts.endpoints/notes. When a control you need to click/fill isn't reachable "
        "by a selector (an obfuscated or canvas UI), build the interaction as a coordinate flow with "
        "visual-driver instead." + _CLICK_FLOW)

    def run(self, ctx, step, runner, provider) -> dict:
        """ADAPTER: map the authenticated surface with the prawlio VISUAL crawl (logio login -> persistent
        session -> click/type through the real UI) and hand the captured request URLs back as endpoints. Falls
        back to the built-in browser exploration (super().run) when there are no credentials or prawlio errors,
        so it only ADDS reach - the unauthenticated pass still works as before."""
        cred_labels = sorted({c["label"] for c in getattr(ctx, "_creds", {}).values()}) \
            if getattr(ctx, "_creds", None) else []
        if not cred_labels:
            return super().run(ctx, step, runner, provider)    # no creds -> unauthenticated exploration (base)
        label = cred_labels[0]
        creds = ctx.creds_for_placeholder(ctx.placeholder_for(label))
        if not creds or ":" not in creds:
            return super().run(ctx, step, runner, provider)
        user, _, pw = creds.partition(":")
        subs = {"__USER__": user, "__PASS__": pw, "__CREDS__": creds}
        headers = list(getattr(runner, "global_headers", []) or [])
        try:
            from ...ai.prawlio import crawl as prawlio_crawl
            say(f"irvin:{self.name}", f"prawlio: authenticated visual crawl as identity {label} on {ctx.base_url}")
            res = prawlio_crawl(provider, ctx.base_url, subs, grid=25, trace=None, headers=headers)
        except Exception as exc:  # noqa: BLE001
            say(f"irvin:{self.name}", f"prawlio errored ({exc}); falling back to the built-in exploration")
            return super().run(ctx, step, runner, provider)
        reqs = res.get("requests") or []
        if not res.get("authenticated") or not reqs:
            say(f"irvin:{self.name}", "prawlio captured nothing / not authenticated; falling back to built-in exploration")
            return super().run(ctx, step, runner, provider)
        endpoints: list = []
        for r in reqs:
            u = r.get("url")
            if u and u not in endpoints:
                endpoints.append(u)
        say(f"irvin:{self.name}", f"prawlio captured {len(reqs)} request(s) -> {len(endpoints)} endpoint(s)")
        return {"findings": [], "verification": {},
                "artifacts": {"endpoints": endpoints,
                              "notes": [f"prawlio authenticated crawl (identity {label}) captured "
                                        f"{len(reqs)} requests across the live UI"]}}

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
        """Pin a browser call to THIS commission's persistent session, and attach the strongest identity's auth
        header so the browser is logged in - both injected at dispatch, so the model never sees the session
        plumbing or the credential/cookie value. visual-driver calls fall through to the base (session + token
        substitution) via super()."""
        if name != "browser-actions":
            return super()._rewrite_call(ctx, name, args)
        new = {**args, "session": self._sid}
        frag = _strongest_identity(ctx)                    # e.g. ["--header", "Cookie: ..."] or []
        ident = [frag[i + 1] for i in range(len(frag) - 1) if frag[i] == "--header"]
        if ident:
            existing = list(args.get("header") or [])
            new["header"] = existing + [h for h in ident if h not in existing]
        return new


class Visor(BrowserExecutor):
    """A PURELY VISUAL login agent - it drives only `visual-driver` and its single goal is to log in with the
    supplied credentials by looking at a coordinate-gridded screenshot and clicking/typing at coordinates with
    human-like mouse motion. Standalone (run it with `boxcutter irvin <target> --agent visor`); it is NOT on
    the IRVIN council and is not commissioned by any suggester - it exists to test the visual driver."""
    name = "visor"
    description = ("Purely visual login: drives ONLY visual-driver, reads a coordinate-grid screenshot, and "
                   "clicks/types at coordinates with human-like motion to log in with the supplied credentials.")
    tools = {"visual-driver"}
    cost = "high"        # a real browser + human-paced motion + a screenshot round-trip per step
    max_steps = 20
    objective = (
        "You are a VISUAL LOGIN operator. Your ONE goal: LOG IN to the target using the supplied credentials, "
        "driving ONLY the `visual-driver` tool - you have no other tools and you never touch DOM selectors. "
        "Each call returns a SCREENSHOT with a red COORDINATE GRID overlaid (x labeled across the top, y down "
        "the left, every 100px). You read an element's position straight off the grid and act by COORDINATE.\n"
        "The session is PERSISTENT and stateful - it stays where you left it across calls (it does NOT "
        "re-navigate; use a `goto` action to move). Work in a tight loop: LOOK at the returned screenshot -> "
        "decide the next action(s) -> execute -> LOOK again. Actions (chain them in ONE call only when they "
        "act on the SAME screen, since every coordinate you pass came from the LAST screenshot): "
        "click:X,Y, dblclick:X,Y, move:X,Y, type:TEXT, key:Enter, scroll:down|up, wait:MS, goto:URL. The mouse "
        "MOVES like a human automatically - you only choose where.\n"
        "TO LOG IN: reach the login form (navigate/scroll if needed and re-screenshot), click the USERNAME "
        "field, type the username token, click the PASSWORD field, type the password token, then click the "
        "submit button. RELEVANT CONTEXT names the exact tokens to type (e.g. __USER_A__ / __PASS_A__) - type "
        "them VERBATIM; they are substituted with the real secret privately at dispatch, so never invent or "
        "guess a real credential. If a field doesn't focus (your next screenshot shows the text didn't land), "
        "re-aim and retry. Handle an identifier-first flow (username, submit, THEN password on the next "
        "screen) by re-screenshotting between steps.\n"
        "CONFIRM against the BACKEND, not the frontend. This is an SPA: the marketing/landing shell loads "
        "without auth, so a screenshot that 'looks logged in' or a bag of pre-login/analytics cookies is NOT "
        "proof. Real success = an authenticated API call succeeds: use the `requests` view / flows to find a "
        "call (a /me, /account, /profile, /orders, /customer... endpoint, often on a different api.* host) that "
        "returns 200 with YOUR user data. The session artifact is usually the JWT the app sends as "
        "`Authorization: Bearer <jwt>` - you'll see it as `req_auth` on that authed flow; put THAT header in "
        "artifacts.tokens (or `Cookie: <session cookies>` for a cookie app). ONLY on a proven authed API call "
        "report success. On failure (a social login you can't complete, MFA/captcha, a field that never "
        "focuses, or no authed API call ever succeeds) say so plainly in artifacts.notes with what the last "
        "screenshot showed, and store NOTHING. A clear, honest outcome is the deliverable - this agent exists "
        "to prove the visual login truly authenticates." + _CLICK_FLOW)

    def __init__(self):
        super().__init__()                             # sets self._sid
        self._grid = None                              # optional grid-spacing override (set by the visor CLI)
        self._trace = None                             # optional trace dir for per-action screenshots (visor CLI)

    def _enrich_step(self, ctx, step: dict) -> dict:
        tgt = ctx.commission_target(step) or ctx.base_url
        if not str(tgt).startswith(("http://", "https://")):
            tgt = ctx.base_url
        labels = sorted({c["label"] for c in ctx._creds.values()})
        if labels:
            toks = "; ".join(f"identity {l}: username={ctx.secret_tokens(l)[0]} password={ctx.secret_tokens(l)[1]}"
                             for l in labels)
            creds_note = (f"Type these tokens to log in (they are substituted with the real secret privately - "
                          f"never type a real credential): {toks}. ")
        else:
            creds_note = ("No credentials were supplied (--creds or in --context), so there is nothing to log "
                          "in with - report that in artifacts.notes and stop. ")
        return {**step, "args": {"target": tgt},
                "context": ((step.get("context") or "") + " "
                            + f"Start URL: {tgt}. {creds_note}Drive it purely by grid coordinates.").strip()}

    def _rewrite_call(self, ctx, name: str, args: dict) -> dict:
        new = super()._rewrite_call(ctx, name, args)       # visual-driver: session pin + secret-token substitution
        if name == "visual-driver":
            if self._grid is not None:
                new["grid"] = self._grid
            if self._trace:
                new["trace"] = self._trace
                new["trace_each"] = True                    # the agent's human trace: a shot after every action
        return new


# -- example calls per executor ------------------------------------------------------------------------------
# Concrete, illustrative invocations shown in each executor's prompt (via Executor.examples) so the model gets
# the call right at a glance. Kept together here for one-look maintenance; args match each tool's real
# agent-facing schema. They are EXAMPLES to adapt to the actual target/params, not literals.
Recon.examples = (
    "dnsx api.example.com   ·   httpx api.example.com   # confirm a host the app references resolves / is live\n"
    "katana-crawl https://example.com --params --js\n"
    "swagger-specs example.com   then   swagger-endpoints https://example.com/openapi.json --fuzzable\n"
    "js-endpoints https://example.com/app.js   ·   graphql-detect example.com")

Spa.examples = (
    "browser-crawl https://example.com                          # render + capture the runtime API\n"
    "visual-driver https://example.com --action wait --action screen --action requests   # if a click is needed to trigger the API\n"
    "http-request https://api.example.com/v1/menu               # sanity-check a captured endpoint")

Dirbust.examples = (
    "http-request https://example.com/no-such-9a7c0f6e          # fingerprint the soft-404 baseline FIRST\n"
    "dirsearch https://example.com   ·   dirb https://example.com   # run both - their wordlists differ\n"
    "http-request https://example.com/admin                     # keep a hit only if it DIFFERS from the baseline")

AccessControl.examples = (
    "http-request https://example.com/api/orders/123 --header 'Authorization: Bearer <A>'  (then <B>)  # BOLA diff\n"
    "http-request https://example.com/api/orders/123            # drop auth: is the record still returned?\n"
    "fuzz \"https://example.com/api/orders/{NUMBERS}\"           # walk object ids")

WebVulnTriage.examples = (
    "fuzz \"https://example.com/search?q=1\"                     # default battery on every param (NO --payload)\n"
    "fuzz \"https://example.com/item?id=1\"                      # id-like params/path, all classes at once\n"
    "http-request \"<candidate url>\"                            # re-issue to confirm the class reproduces")

Sqli.examples = (
    "fuzz \"https://example.com/item?id=1\"                      # reproduce the injection point first\n"
    "sqlmap \"https://example.com/item?id=1\" --opt-args \"--batch --dbs\"\n"
    "sqlmap \"https://example.com/item?id=1\" --opt-args \"--batch -D app -T users --dump -C email\"")

Xss.examples = (
    "fuzz \"https://example.com/search?q=1\"                     # default scanner: fire the built-in XSS battery (plain, NO --payload)\n"
    "http-request \"https://example.com/search?q=xY9z\\\"><svg/onload=alert(1)>\"   # tailored: re-issue a reflecting payload, unique marker\n"
    "# then READ the returned 'content': the marker must appear UNESCAPED (not &lt;svg&gt;) in an executing context")

PathTraversal.examples = (
    "fuzz \"https://example.com/download?file=1\"                # default scanner: fire the built-in traversal/LFI battery (plain)\n"
    "http-request \"https://example.com/download?file=../../../../etc/passwd\"   # tailored: read the body for root:x:0:0\n"
    "http-request \"https://example.com/read?path=php://filter/convert.base64-encode/resource=config.php\"  # decode base64 body")

GitDumper.examples = (
    "http-request https://example.com/.git/HEAD   and   /.git/config   # confirm a REAL repo, not a catch-all 200\n"
    "git-extract https://example.com/                           # reconstruct the working tree\n"
    "scan-secrets https://example.com/config.php               # scan recovered source for creds/keys")

Secrets.examples = (
    "js-endpoints https://example.com/app.js                    # expand a bundle's references\n"
    "http-request https://example.com/app.js   then   scan-secrets https://example.com/app.js\n"
    "scan-secrets https://example.com/config.json")

Exposure.examples = (
    "nuclei https://example.com --tags exposure,misconfig,cve\n"
    "http-request https://example.com/no-such-9a7c0f6e          # baseline the soft-404 first\n"
    "http-request https://example.com/.env   ·   /actuator/health   ·   /server-status")

Auth.examples = (
    "browser-login https://example.com/login <cred-placeholder>   # simple single-page form\n"
    "browser-actions https://example.com/login --action screenshot --action describe   # SEE the page + list fields\n"
    "browser-actions https://example.com/login --action 'fill:#user=<placeholder>' --action 'click:text=Next' "
    "--action 'waitfor:#pass' --action 'fill:#pass=<placeholder>' --action 'click:button[type=submit]'\n"
    "visual-driver https://example.com --action screen --action 'click_text:Log in' --action wait:3 --action screen "
    "--action 'click:600,375' --action 'put:__USER_A__' --action 'click:600,460' --action 'put:__PASS_A__' "
    "--action 'click_text:Log in'   # buttons BY TEXT (find 'Log in', not 'Sign up'), fields by coordinate")

Explorer.examples = (
    "browser-actions https://example.com --action screenshot --action 'click:text=Orders' --action requests\n"
    "browser-actions https://example.com --action requests:api.example.com   # list one backend host's calls\n"
    "visual-driver https://example.com --action screen --action 'click:400,300'   # a control with no stable selector")

Visor.examples = (
    "visual-driver https://example.com --action wait --action screen               # see the gridded page\n"
    "visual-driver https://example.com --action 'click_text:Log in' --action wait:3 --action screen   # Log in, NOT Sign up\n"
    "visual-driver https://example.com --action 'click:600,375' --action 'put:__USER_A__' --action 'click:600,460' "
    "--action 'put:__PASS_A__' --action 'click_text:Log in' --action wait --action screen")

"""irvin executors - PROFESSIONAL specialists, one per security ISSUE, who answer a manager's commission
with STRICTLY VERIFIED results.

Each executor owns one area (recon, content discovery, access control, OWASP-breadth triage, SQLi, XSS,
path-traversal/LFI, exposed VCS, secrets, misconfiguration) - NOT a tool. It carries only the tools coherent
with its issue and uses them as instruments; the agentic loop + the self-verification contract (finding
re-test, and the catch-all/ghost path check for path-guessers) live in base.Executor. Adding an executor is
one class here + one line in agents/__init__.py.
"""

from __future__ import annotations

from .base import Executor


class Recon(Executor):
    name = "recon"
    description = "Reconnaissance (attack surface): the linked/spec/JS-derived surface with method+params+auth, deduped and existence-gated."
    tools = {"httpx", "http-request", "katana-crawl", "js-endpoints", "swagger-specs",
             "swagger-endpoints", "graphql-detect"}
    verify_paths_exist = True       # the agentic existence gate is the authoritative liveness check at handoff
    max_steps = 16
    objective = (
        "You are a RECONNAISSANCE specialist - your deliverable is the target's LINKED, spec-derived and "
        "JS-derived attack surface, never an invented one (unlinked brute paths are dirbust's lane). Prefer "
        "authoritative sources: enumerate every operation an OpenAPI/GraphQL schema declares, confirm liveness "
        "and fingerprint the stack, crawl for routes and query parameters, and mine every in-scope JS bundle for "
        "API paths. Treat a spec as a baseline and DIFF it against crawl/JS-observed routes, flagging "
        "stale/partial gaps. Stay in-scope-host-only (drop or flag off-host URLs). For each endpoint capture the "
        "HTTP method, observed params/body shape, and auth-required-vs-anonymous. Hand off FACTS: drop asset "
        "URLs (.js/.css/.png/.woff) and duplicates (same normalized path+method) - the existence gate confirms "
        "the survivors - and return the distinct set with a raw->kept count in artifacts.endpoints.")


class Dirbust(Executor):
    name = "dirbust"
    description = "Content discovery: unlinked paths proven to EXIST vs the soft-404 baseline, classified - sensitivity is not its call."
    tools = {"dirsearch", "dirb", "http-request"}
    verify_paths_exist = True       # brute output is noisy AND 200-on-miss hosts lie - confirm each really exists
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
        "Drive `fuzz` against every query parameter and id-like path segment, reasoning from a class-specific "
        "differential, not a bare status:\n"
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
        "endpoint, unauthenticated admin/debug panel; nuclei is one corroborating means, not the mission. You do "
        "NOT re-brute (dirbust's lane) and do NOT dump .git or scan for secrets (git-dumper/secrets own those). "
        "Take the mapped + dirbust surface plus a SMALL FIXED well-known checklist - no product-name "
        "extrapolation (e.g. /mantisBT/), no probing beneath a 404 dir. Before declaring a path real, baseline "
        "the host's soft-404 and require a hit to differ in status/length/Content-Type; tell a real "
        "listing/disclosure apart from a framework error/login page that returns 200. 'Sensitive' = "
        "credentials/keys, source/backups, internal hosts/IPs, stack traces with paths, env/config, or an "
        "unauthenticated console; quote the redacted snippet as proof and drop generic 200s and template "
        "false-positives.")

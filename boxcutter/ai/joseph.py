"""joseph - a HUMAN-OPERATOR agent (peer to bob / caleb / vera under `boxcutter ai <name>`).

Where bob/caleb/vera are mechanical tool-drivers (a fixed menu, one call at a time, mostly stateless, no
code of their own), joseph is an OPERATOR: one litellm brain both DECIDES and ACTS. It

  - inhabits a LIVE browser session (core/cdp `_SESSIONS`) kept logged in, state accumulating;
  - routes all traffic through a bundled ZAP daemon (ai/_zapproxy) so every request is captured + replayable;
  - drives the FULL boxcutter tool registry (not bob's narrow allowlist), via native per-tool schemas;
  - AUTHORS capability - writes and runs its own Python/shell in the container against the held session;
  - persists everything to a per-run WORKSPACE folder it reads back from (sessions/ flows/ scripts/ tools/
    findings/ + an append-only run.jsonl).

The commitment that unlocks this (design §9): safety is BOUNDARY-based, not allowlist-based. The container +
the scope ARE the guardrail - arbitrary scripts and the full tool set are fine because they can't escape the
container and egress is scope-limited. joseph MAY mutate (POST/PUT/DELETE) within scope; every mutation is
logged. `--dry-run` gates all mutation for a first look.

CENTREPIECE - the REASONING STREAM (design §16). joseph THINKS OUT LOUD. Before every action it narrates, in
the live stream and in run.jsonl, a disciplined micro-cycle: OBSERVE (the exact value/status seen) -> INTERPRET
(what it means vs. a baseline) -> TRACE (how a value flows) -> HYPOTHESIZE (a checkable claim + predicted
observable + control) -> PLAN (the specific next checks) -> ACT. That transparent reasoning log - the
investigation, the dead-ends, the "this looked exploitable but React escapes it" - is a first-class deliverable,
not a byproduct.

This is a FULL-IMAGE tool (needs chromium + ZAP); it degrades gracefully where they are absent.

  boxcutter ai joseph https://app.example.com --provider litellm --model openai/gpt-5 --api-key ... \
      --llm-proxy-url ... --creds admin:pass --max-rounds 4 --out-dir ./joseph_app
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..core import agentlog, cdp, scope
from ..core.envelope import debug_print, output_result
from ..irvin import briefing
from ..irvin.context import extract_json
from ..forge import report as fr
from ..tools import toolschema
from . import _zapproxy, skills
from .provider import PROVIDERS, add_agent_args, make_provider, reset_usage, usage_cost

NAME = "joseph"
KIND = "findings"
HELP = ("Joseph - human-operator agent: a live browser + ZAP + the full tool registry + in-container "
        "scripting, driven by ONE litellm brain that THINKS OUT LOUD (a transparent reasoning stream) "
        "and acts - inhabiting a session like a human pentester, not a scanner.")

# Agentic sub-commands joseph must NOT drive (non-goal §14: joseph is an operator, not a conductor over the
# other agents) and the pure-infra scanners (web + HTTP + the held browser only, §14). Everything else in the
# registry is fair game; the guardrail is the boundary (scope + container), not the menu (§9).
_EXCLUDE_TOOLS = {"nmap", "ping-scan"}

# boxcutter runs tools IN-PROCESS via its own CLI, redirecting sys.stdout to capture the JSON envelope. That
# redirect is a PROCESS-GLOBAL swap, so two threads (the driver + an analyst) calling tools at once would
# clobber each other's capture. Serialize just the in-process CLI call; the expensive part - the concurrent
# LLM "thinking" - still overlaps (design §17).
_CLI_LOCK = threading.Lock()

# The tools an ANALYST may drive - EVERY non-destructive boxcutter tool (discovery + the non-destructive
# scanners fuzz/sqlmap/nuclei/bola-walk/blind-oracle), so a lane can CONFIRM in its class, not just flag. What
# stays the DRIVER's alone: the live session (session_*), the request-mutation primitive (mutate_replay),
# state-changing mass-assign, the heavy active zap-scan-*, and the browser-driven tools. http-request is
# GET-only for an analyst (see _readonly_args). Analysts still never write the live session (one-writer, §17).
_ANALYST_TOOLS = ["http-request", "katana-crawl", "api-map", "path-bust", "path-fuzz", "dirsearch", "dirb",
                  "wayback", "httpx", "smart-enum", "js-endpoints", "scan-secrets", "git-extract",
                  "swagger-specs", "swagger-endpoints", "graphql-detect", "graphql-audit",
                  "fuzz", "sqlmap", "nuclei", "bola-walk", "blind-oracle"]

# The full ANALYST-LANE catalog - one focused read-only reviewer per analysis domain boxcutter has tools and
# skills for. `--analysts N` runs the first N (default: all). Each lane names the tools/skills it leans on so
# the split of labour is clear; active exploitation (fuzz/sqlmap/mutate/console) is always the DRIVER's job.
_ANALYST_LANES = [
    ("recon-surface",
     "the RECON / attack-surface analyst. Map the reachable surface from the bus and extend it: drive "
     "katana-crawl, api-map, path-bust, js-endpoints and wayback to enumerate endpoints, hidden/unlinked "
     "paths, shadow/versioned APIs (/v1 vs /v2, /internal, /beta) and every param-bearing URL. Emit each "
     "interesting endpoint as a lead saying WHY it merits active testing."),
    ("js-xss",
     "the JS / DOM-XSS / client-side analyst (the juicy / frontend-security lane). DOWNLOAD the app's OWN "
     "custom bundles: http-request every <script src> the page loads (each auto-archives to js/), then "
     "workspace_read them and read the code AS SOURCE - skip vendor/framework noise, focus on the app's own "
     "code. Run js-endpoints on each for hidden URLs and scan-secrets for leaked keys/config. TRACE URL "
     "params, location.hash and postMessage into raw-HTML or script sinks (innerHTML, document.write, eval, "
     "v-html, dangerouslySetInnerHTML, bypassSecurityTrust, runtime-compiled templates); frameworks escape by "
     "default, so a lead exists only where code LEAVES that baseline. Report the exact source -> sink path, "
     "plus CSTI, prototype-pollution and open-redirect candidates, and any sourcemap that exposes the "
     "un-minified source."),
    ("auth-idor",
     "the auth / access-control analyst (the authz lane). Read the flows on the bus; find "
     "id-bearing endpoints (missing ownership checks = IDOR/BOLA), low-priv paths that reach a privileged "
     "action (BFLA), and token/JWT weaknesses (alg:none, weak/leaked secret, un-verified role/is_admin "
     "claims). Emit leads to probe DIFFERENTIALLY as A vs B vs anon."),
    ("sqli",
     "the SQL-INJECTION analyst. Hunt every param that could reach a query - ?id=, numeric / id path "
     "segments, search / filter / sort fields, JSON body fields. FUZZ each (it self-confirms by re-firing), "
     "then run SQLMAP on the exact injectable request for the BLIND / time-based cases fuzz cannot see. On a "
     "confirmed SQLi, note the extractable table and hand the driver the exact request + param so it can "
     "--dump the credential table and chain the recovered creds."),
    ("injection",
     "the (non-SQL) injection analyst. Read discovered params / endpoints / bodies on the bus; FUZZ the exact "
     "inject point (?param=, an id path segment, a body field, an XML/import body) for SSTI / LFI / XXE / "
     "NoSQL / command-injection, and confirm with a benign marker that only resolves if it actually executed."),
    ("secrets",
     "the secrets / exposure analyst (the scan-secrets / git-extract / nuclei-exposure lane). Scan bundles "
     "and responses on the bus for leaked keys/tokens/JWT-signing-secrets/config; probe the well-known leak "
     "points (/.git/, /.env, /actuator/env, backups, source maps, heapdumps) and emit each as a lead."),
    ("api-graphql",
     "the API / GraphQL analyst. From swagger-specs / swagger-endpoints and graphql-detect on the bus, map "
     "the DECLARED surface; flag introspection, query batching, excessive-data and argument-injection "
     "candidates, and every spec endpoint that must be access-tested."),
    ("business-logic",
     "the business-logic analyst. From the mapped operations on the bus, flag any state-changing op that "
     "trusts a client value - money/quantity/price/discount/status/role, mass-assignment fields, coupon "
     "reuse, unsigned webhooks - naming the field to tamper and the expected abuse."),
    ("ssrf-redirect",
     "the SSRF / open-redirect analyst. Find url/callback/webhook/next/redirect params and Host / "
     "X-Forwarded-* / X-Original-URL header vectors on the bus; enumerate the exact vector set (header AND "
     "param variants) for the driver to test against an out-of-band canary - the class scanners under-cover it."),
]

# Each lane PRELOADS the boxcutter vuln-class PLAYBOOK(s) (ai/skills/*.md via skills.load) for its domain, so an
# analyst carries the deep methodology (payloads, steps, gotchas) of its class - not just its one-line brief.
# Names are skills.REGISTRY keys; every registered playbook is owned by at least one lane. The DRIVER instead
# pulls playbooks on demand (load_skill), since it works across all classes toward the goal.
_LANE_SKILLS = {
    "recon-surface": ["info_disclosure", "swagger"],
    "js-xss": ["xss", "prototype-pollution", "open-redirect", "cors"],
    "auth-idor": ["idor", "auth", "jwt", "missing-auth", "privesc", "crypto"],
    "sqli": ["sqli"],
    "injection": ["injection", "ssti", "lfi", "xxe", "nosql", "rce", "http_injection", "deserialization",
                  "file-upload"],
    "secrets": ["secrets", "info_disclosure"],
    "api-graphql": ["graphql", "swagger"],
    "business-logic": ["business_logic", "race_condition"],
    "ssrf-redirect": ["ssrf", "open-redirect"],
}

# The REAL wordlists + hash-cracker shipped in the image, documented so the operator / analysts / any script they
# write point --wordlist (or a login-brute / hash-crack loop) at a path that EXISTS - there is NO seclists or
# rockyou here, and an invented --wordlist just silently falls back to a tool's default. Surfaced in the brief.
_WORDLISTS_ON_DISK = (
    "TOOLING ON DISK (real paths - use these, never invent seclists/rockyou; an unknown --wordlist just falls "
    "back to a tool's default):\n"
    "- PATH / DIR lists (for path-bust/path-fuzz/dirb --wordlist, or a script):\n"
    "    /opt/boxcutter/boxcutter/data/wordlist.txt      (~13k breadth paths; path-bust --full uses it)\n"
    "    /opt/boxcutter/boxcutter/data/api_wordlist.txt  (~8k API routes)\n"
    "    /usr/share/dirb/wordlists/common.txt            (dirb default; the dir holds big.txt, vulns/, ...)\n"
    "    /usr/share/dirsearch/db/dicc.txt                (dirsearch's bundled list)\n"
    "    (path-bust/path-fuzz also carry a ~950-word curated built-in used when you OMIT --wordlist)\n"
    "- SUBDOMAIN list: /opt/boxcutter/boxcutter/data/subdomains.txt (~1k; dns-brute/dnsx default)\n"
    "- PASSWORD lists (login brute-force / spraying, and cracking recovered hashes):\n"
    "    /opt/boxcutter/boxcutter/data/passwords_10k.txt (~10k - fast first pass)\n"
    "    /opt/boxcutter/boxcutter/data/passwords.txt     (~2.3M - broad, slower)\n"
    "- HASH CRACKER (crack-js): a hash you recover (a SQLi credential dump, a leaked shadow/htpasswd line, an "
    "HS256 JWT secret guess) cracks against those password lists via:\n"
    "    node /usr/share/crack-js/crack.js <hash> /opt/boxcutter/boxcutter/data/passwords_10k.txt [mode]\n"
    "    (mode = a hashcat number e.g. 0=MD5 100=SHA1 1400=SHA256 1000=NTLM 3200=bcrypt, or a name; OMIT it to "
    "auto-detect. It prints one JSON line {\"cracked\":true,\"plaintext\":\"...\"}. Call it from a "
    "write_script/run_script shell script.)")


def _real_tool_names() -> list[str]:
    """The deterministic boxcutter tools joseph may drive - the whole registry minus the agentic commands
    (it drives raw tools + its own scripts, not the other agents) and the infra scanners (web-only scope)."""
    from ..tools.registry import AI, BY_NAME
    ai_names = {getattr(m, "NAME", "") for m in AI}
    return [n for n in BY_NAME if n not in ai_names and n not in _EXCLUDE_TOOLS]


# -- the non-tool actions (session + meta), handed to the model in the SAME native shape as a real tool -------
_SESSION_ACTIONS = [
    {"name": "session_open",
     "description": "Open (or attach to) joseph's persistent Chrome for this run and navigate to a URL. The "
                    "browser stays alive and logged in across the whole run; its traffic is captured. Returns "
                    "{fresh, status, title, url}.",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"url": {"type": "string", "description": "URL to navigate to"},
                               "identity": {"type": "string", "enum": ["A", "B"],
                                            "description": "Which live identity/window (default A)"}},
                "required": ["url"]}},
    {"name": "session_do",
     "description": "Drive the live browser. steps is a list of 'verb:arg' strings executed in order: "
                    "'navigate:<url>', 'click:<css-selector>', 'fill:<css-selector>=<value>', 'find:<text>' "
                    "(is this text present?), 'wait:<seconds>'. Only joseph's session actions mutate the "
                    "browser (one writer).",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"steps": {"type": "array", "items": {"type": "string"},
                                         "description": "ordered 'verb:arg' steps"},
                               "identity": {"type": "string", "enum": ["A", "B"]}},
                "required": ["steps"]}},
    {"name": "session_read",
     "description": "Read-only view of the live session (does NOT mutate it). what in: 'flows' (new "
                    "request/response exchanges since the last read, incl. the bearer the SPA sent), "
                    "'requests' (proxy-like host map), 'dom' (rendered HTML), 'storage' (local/session "
                    "storage), 'cookies', 'form' (describe the current form), 'title', 'url', 'screenshot' "
                    "(saved to the workspace).",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"what": {"type": "string",
                                        "enum": ["flows", "requests", "dom", "storage", "cookies", "form",
                                                 "title", "url", "screenshot"]},
                               "identity": {"type": "string", "enum": ["A", "B"]}},
                "required": ["what"]}},
]

_META_ACTIONS = [
    {"name": "write_script",
     "description": "Author a script in the run workspace (scripts/<name>). Use it when the built-in tools "
                    "don't fit: a bespoke fuzz loop, a payload generator, a multi-request chain. language in "
                    "{python, shell, node}. node runs under Node.js and can `require('crack-js')` (the hash "
                    "cracker) directly. The script is captured as an artifact. Name it with the matching "
                    "extension (.py/.sh/.js) so the language is unambiguous.",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"name": {"type": "string", "description": "file name, e.g. walk_ids.py / "
                                        "crack.js / probe.sh"},
                               "language": {"type": "string", "enum": ["python", "shell", "node"]},
                               "source": {"type": "string", "description": "the full script source"}},
                "required": ["name", "language", "source"]}},
    {"name": "run_script",
     "description": "Run a script written with write_script, in the container against the held session (python, "
                    "shell, or node - the language is remembered from write_script). It gets an injected env: "
                    "JOSEPH_TARGET, JOSEPH_WORKSPACE, HTTP(S)_PROXY + REQUESTS_CA_BUNDLE (so its traffic is "
                    "captured), and the held session's cookie/bearer (JOSEPH_COOKIE / JOSEPH_BEARER) so it acts "
                    "AS the logged-in user. Returns stdout/stderr/exit + any files it dropped in the workspace. "
                    "Bounded by --script-timeout and --max-scripts.",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"name": {"type": "string"},
                               "args": {"type": "array", "items": {"type": "string"}},
                               "timeout": {"type": "integer", "description": "wall-clock seconds (<= cap)"}},
                "required": ["name"]}},
    {"name": "mutate_replay",
     "description": "Take a captured request and replay an edited copy through ZAP (so the replay is captured "
                    "too). Give a full url + method, optional headers (list of 'K: V') and body. This is the "
                    "request-mutation primitive. Mutating methods are refused under --dry-run.",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"url": {"type": "string"},
                               "method": {"type": "string",
                                          "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]},
                               "headers": {"type": "array", "items": {"type": "string"}},
                               "body": {"type": "string"}},
                "required": ["url"]}},
    {"name": "workspace_read",
     "description": "Read back a file under the run workspace (a tool output, a script result, a captured "
                    "flow, a note) so you can operate on your own accumulated data.",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"path": {"type": "string", "description": "path relative to the workspace"}},
                "required": ["path"]}},
    {"name": "workspace_list",
     "description": "List files under the run workspace (optionally filtered by a glob like 'flows/*').",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"glob": {"type": "string"}}, "required": []}},
    {"name": "load_skill",
     "description": "Load a boxcutter vuln-class PLAYBOOK into your context by name - the deep methodology for a "
                    "class (the exact payloads, the steps, the confirmation markers, the gotchas). Call it the "
                    "moment you commit to hunting a class, so you probe it the way the playbook says, not from "
                    "memory. Returns the playbook body; unknown names return the available list.",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"name": {"type": "string",
                                        "description": "class/skill name, e.g. sqli, idor, ssrf, jwt, ssti"}},
                "required": ["name"]}},
    {"name": "note",
     "description": "Append a lead / observation to the run store (not a finding - a thread to pull later).",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"kind": {"type": "string"}, "detail": {"type": "string"}},
                "required": ["detail"]}},
    {"name": "finding",
     "description": "Record a CONFIRMED finding as a PROFESSIONAL REPORT ENTRY (design §7/§11). A finding is real "
                    "only via this call plus a replayable exchange. Write it the way a bug-bounty / pentest "
                    "writeup reads: a `summary` of what the vuln is + where + the mechanism, ordered `steps` to "
                    "reproduce, a runnable `poc` (curl and/or a python snippet), the demonstrated `impact` (what "
                    "an attacker gains, tied to the concrete evidence you observed), and concrete `remediation`. "
                    "Include the exact url, the predicted_observable you checked, and the observed evidence.",
     "schema": {"type": "object", "additionalProperties": False,
                "properties": {"severity": {"type": "string", "enum": ["High", "Medium", "Low", "Suggestion"]},
                               "title": {"type": "string"}, "url": {"type": "string"},
                               "cls": {"type": "string", "description": "vuln class, e.g. sqli / idor / xss / "
                                       "ssrf / jwt (drives the CWE + CVSS tag)"},
                               "summary": {"type": "string", "description": "2-4 sentences: what the vuln is, the "
                                           "exact endpoint/param, and the mechanism (how the input reaches the sink)"},
                               "steps": {"type": "array", "items": {"type": "string"},
                                         "description": "ordered steps to reproduce"},
                               "poc": {"type": "string", "description": "a runnable proof-of-concept - curl "
                                       "and/or a python snippet an operator can paste and run"},
                               "impact": {"type": "string", "description": "the demonstrated impact - what an "
                                          "attacker gains, backed by the concrete observations"},
                               "remediation": {"type": "array", "items": {"type": "string"},
                                               "description": "concrete fixes (allowlist, static config, ...)"},
                               "predicted_observable": {"type": "string"},
                               "evidence": {"type": "string", "description": "the observed proof (redacted)"}},
                "required": ["severity", "title", "evidence"]}},
]

_SYSTEM = (
    "You are JOSEPH, a HUMAN-OPERATOR security agent. You are NOT a scanner walking a checklist - you are a "
    "pentester sitting in front of the app: you open a real browser, stay logged in, watch the traffic as you "
    "click, reuse a value the moment you see it, and when the built-in tools run out you WRITE AND RUN YOUR OWN "
    "SCRIPT. You DECIDE and you ACT, in one live session, against accumulated state.\n\n"

    "GOAL-DIRECTED. Your input is a MISSION BRIEF - the GOAL, the ENDPOINTS in play, and how to AUTHENTICATE - "
    "not just a URL. Read the goal and drive toward ACHIEVING it (reach the described outcome / flag / data / "
    "capability), not toward a generic scan. When the brief names endpoints and credentials, START there. "
    "Every action serves the goal; when you have achieved it, prove it with evidence and finish.\n\n"

    "THE MOST IMPORTANT RULE - THINK OUT LOUD, EVERY TURN, BEFORE YOU ACT.Your reasoning is a first-class "
    "DELIVERABLE, not a preamble to skip. Before every action, write a short narrative that walks this "
    "micro-cycle explicitly:\n"
    "  1. OBSERVE - the concrete thing you just saw, with the EXACT evidence: the literal status, string, "
    "value, header, or code you are reacting to (e.g. \"/.git/config returned the HTML SPA shell, not a git "
    "config - the CDN serves the same cached HTML for every path\"; \"found o1=e=>new "
    "URLSearchParams(location.search).get(e), called as o1('id')\").\n"
    "  2. INTERPRET - what it MEANS against a baseline (a 200 that matches the catch-all is the front "
    "controller, not a finding; a value that flows through React's escaping is likely safe).\n"
    "  3. TRACE - follow the value: where does this input go, through which function, into which sink/query "
    "(e.g. \"id -> Ere -> t#${t} -> GraphQL variable -> subscription channel\").\n"
    "  4. HYPOTHESIZE - a CHECKABLE claim with a predicted_observable and a control: \"if it reaches a raw-HTML "
    "sink, ?id=<img src=x onerror=..> fires; control: a benign id does not\".\n"
    "  5. PLAN - the specific next checks, enumerated (\"read the small config bundles as source, grep for "
    "postMessage handlers, fetch /sw.js, then open the page live and inspect the DOM + network\").\n"
    "  6. ACT - take the ONE concrete action now.\n"
    "Ruling something OUT, with the reason, is as valuable as a finding - say it, don't go silent. A turn that "
    "acts without this narrative is incomplete.\n\n"

    "INHABIT THE LIVE SESSION. Use session_open once, then session_do to click/fill/navigate and session_read "
    "to watch flows/dom/storage/cookies. Observation is AMBIENT - after any action, session_read 'flows' to see "
    "the new request/response traffic (it carries the bearer the SPA sent). Reuse what you see immediately: a "
    "token in one response is your key to the next endpoint IN THE SAME SESSION.\n\n"

    "AUTHOR CAPABILITY - YOU HAVE FULL ACCESS INSIDE THE CONTAINER. When a built-in tool doesn't fit the exact "
    "thing you want to try, write_script a small Python (it has requests; JOSEPH_TARGET / JOSEPH_COOKIE / "
    "JOSEPH_BEARER / the proxy env are injected so it acts as the logged-in user and its traffic is captured) "
    "and run_script it (language python, shell, or node - a node script can require('crack-js') to crack a "
    "recovered hash against the on-disk password lists). You may create files anywhere, read the filesystem - the "
    "container is your box, so work as freely inside it as a pentester on their own machine. Read your own "
    "accumulated data back with workspace_read / workspace_list and the dumped session files "
    "(sessions/<id>/cookies.txt, localStorage.json). A 15-line bespoke fuzz loop, an SSRF-vector sweep, or a "
    "multi-request chain you write yourself is often stronger than any menu tool - that is your operator edge. "
    "The container is the boundary (you cannot escape it and egress is scope-limited); within it you are "
    "unconstrained. curl, git, python3 (with requests) and the usual CLI tools are ALREADY INSTALLED - call "
    "them from a shell script or a subprocess whenever they are the quickest path.\n\n"

    "EXAMPLES of the tooling you author (write REAL Python / curl like this, not pseudocode - then run_script "
    "it, read the output, and act on it):\n"
    "```python\n"
    "# scripts/ssrf_headers.py - sweep header SSRF vectors as the logged-in user; print status+len per vector\n"
    "import os, requests\n"
    "base = os.environ['JOSEPH_TARGET']; bearer = os.environ.get('JOSEPH_BEARER', '')\n"
    "h = {'Authorization': bearer} if bearer else {}\n"
    "cookie = os.environ.get('JOSEPH_COOKIE', '')\n"
    "if cookie:\n"
    "    h['Cookie'] = cookie\n"
    "for vec in ['X-Forwarded-Host', 'X-Original-URL', 'X-Forwarded-For', 'Forwarded', 'X-Rewrite-URL']:\n"
    "    r = requests.get(base + '/api/notifications', headers={**h, vec: 'oob-canary.example'})\n"
    "    print(vec, r.status_code, len(r.text))\n"
    "```\n"
    "```sh\n"
    "# scripts/probe.sh - reuse the dumped session material + the installed curl\n"
    "cat \"$JOSEPH_WORKSPACE/sessions/joseph_A/cookies.txt\"\n"
    "curl -s -H \"Authorization: $JOSEPH_BEARER\" \"$JOSEPH_TARGET/api/me\" | head -c 400\n"
    "```\n\n"

    "DRIVE THE FULL TOOL SET. You have the whole boxcutter registry (recon, crawl, katana, fuzz, sqlmap, "
    "nuclei, graphql-*, swagger-*, harvest, http-request, the zap-* scanners, browser-*). Their arg schemas "
    "are provided. Use http-request as your scalpel to confirm; use mutate_replay to edit-and-resend a captured "
    "request through ZAP. The moment you commit to a vuln class, load_skill(name) to pull its deep PLAYBOOK "
    "(exact payloads, steps, confirmation markers, gotchas) and hunt it that way, not from memory.\n\n"

    "HIGH-VALUE PLAYS - fire these the moment the trigger appears (the tool schemas give the exact args; the "
    "analysts will also feed you leads for them):\n"
    "  - SQL INJECTION: on ANY param that could reach a query (?id=, ?q=, a numeric/id path segment, a search "
    "/ filter / sort field, a JSON body field), FUZZ it first (fuzz self-confirms by re-firing), then run "
    "SQLMAP on the exact injectable request as the second opinion for the BLIND / time-based cases fuzz cannot "
    "see. A confirmed SQLi is the START, not the end - EXTRACT with it: sqlmap --opt-args \"--dump\" / "
    "\"--passwords\" pulls the user/credential table, and those creds feed the credential-reuse chain (log in, "
    "then walk the authed/admin surface). If the recovered passwords are HASHED, crack them with crack-js "
    "against the on-disk password lists (your brief has the exact command) and reuse the plaintext. Write your "
    "own UNION/blind script if sqlmap can't run.\n"
    "  - IDOR / BOLA: on any id-bearing endpoint, walk neighbouring ids as A vs B vs anon - another user's "
    "object coming back is the finding.\n"
    "  - BROKEN AUTH / JWT: replay a handed-out token on gated endpoints; try alg:none and un-verified "
    "role/is_admin claims; if a signing secret leaked, that is an HS256 admin-forge chain.\n"
    "  - OTHER INJECTION (SSTI / LFI / XXE / NoSQL / command): fuzz the exact inject point; confirm with a "
    "benign marker that only resolves if it executed (arithmetic, a file read, an echoed token).\n"
    "  - BUSINESS LOGIC / MASS-ASSIGNMENT: tamper a client-controlled money/qty/price/status/role value or "
    "inject privileged fields, and check the server trusts it.\n"
    "Each confirmed bug is a hop, not a stop - re-scan your whole inventory (creds, tokens, ids, secrets, "
    "endpoints) after every finding and compose the multi-hop chains toward the GOAL.\n\n"

    "OBSERVE, DON'T ASSUME. Every app differs - its auth flow, endpoint names, token scheme, where the API "
    "lives. DISCOVER by observation (read the JS bundle for the REAL paths; watch which request returns a token "
    "or mutates a value) and confirm every lead by BEHAVIOUR. A hint that doesn't match this app tells you "
    "which behaviour to go find; follow what you observe.\n\n"

    "EVIDENCE AND THE VALIDATION GATE. Power without discipline is noise. For any claim, state the "
    "predicted_observable and the control BEFORE you fire, then check the captured exchange. Call finding(...) "
    "ONLY for a claim whose prediction passed, and attach the replayable evidence. For access-control classes, "
    "prefer a differential: the same request as A, as B, as anon. An unproven claim is worth zero - either "
    "prove it or record it as a note/open lead, never as a finding.\n\n"

    "SAFETY - BOUNDARY, NOT MENU. You operate inside an authorised container on an in-scope target, so you MAY "
    "POST/PUT/DELETE within scope when a human tester would - but every mutation is logged, and you stay ON the "
    "target's host and the API/backend hosts it itself calls (never unrelated third-party hosts). Confirm with "
    "the least-intrusive benign proof; never be destructive (no data deletion, no DoS, no writes beyond a "
    "throwaway test account). If --dry-run is on, do not mutate - map and predict instead.\n\n"

    "BUDGET: coverage over frugality. Do not skip a check to save a call; only avoid exact duplicates and "
    "provably useless calls. Batch independent actions in one turn.\n\n"

    "REPORT LIKE A PROFESSIONAL. Each confirmed finding must read like a bug-bounty / pentest writeup, not a "
    "one-liner: a SUMMARY (what the vuln is, the exact endpoint/param, and the mechanism - how the input "
    "reaches the sink), ordered STEPS to reproduce, a runnable POC (curl and/or a python snippet an operator "
    "can paste and run), the demonstrated IMPACT (what an attacker gains, tied to the concrete evidence you "
    "observed), and concrete REMEDIATION. Record each via finding(...) as you confirm it, and also list them in "
    "the final JSON below - joseph tags the CWE + a CVSS heuristic and renders the full writeup from these.\n\n"

    "FINISH: when you are done, reply with NO action and ONE fenced ```json block (nothing else) with EXACTLY "
    "these fields (joseph renders the report from it):\n"
    "```json\n"
    "{\n"
    '  "application": {"description":"<2-4 sentences: what the app does + purpose>","stack":"<framework/lang '
    '| server | CDN/WAF | notable libs>","api":"<REST / GraphQL / RPC / none>","auth":"<cookie / JWT / OAuth '
    '/ none observed>"},\n'
    '  "findings": [{"severity":"High|Medium|Low|Suggestion","title":"<short>","url":"<url>","cls":"<class '
    'e.g. ssrf/jwt/idor/sqli>","summary":"<2-4 sentences: what + where + mechanism>","steps":["<ordered '
    'reproduction step>","..."],"poc":"<runnable curl and/or python>","impact":"<what an attacker gains, tied '
    'to the observed evidence>","remediation":["<concrete fix>","..."],"evidence":"<=280 chars, redacted '
    'proof>"}],\n'
    '  "investigation": "<3-8 sentences: what you looked at, what you RULED OUT and why, what you confirmed - '
    'the story of the session>",\n'
    '  "coverage": "<one line: what you actually checked>",\n'
    '  "bottom_line": "<one sentence: the single biggest problem, or nothing obviously exposed>"\n'
    "}\n```\n"
    "Only proven findings go in `findings`. Redact secret values (joseph masks known secret shapes too). If "
    "nothing survived the gate, give an empty list and say so in bottom_line.")


def _cap(raw: str, max_chars: int = 60000) -> str:
    """Bound a single tool/action result so one huge body can't blow the context window."""
    s = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    return s if len(s) <= max_chars else s[:max_chars] + f"\n...[+{len(s) - max_chars} chars truncated]"


def _digest(raw: str, limit: int = 400) -> str:
    """A short digest of an action result for the run.jsonl trace (the full result lands in tools/ / flows/)."""
    s = " ".join((raw or "").split())
    return s if len(s) <= limit else s[:limit] + " ..."


def _as_list(v) -> list:
    """Coerce a model-supplied steps/remediation value to a clean list of strings (it may arrive as a string,
    a newline/numbered block, or already a list)."""
    if not v:
        return []
    if isinstance(v, str):
        parts = [re.sub(r"^\s*(?:\d+[.)]|[-*])\s*", "", ln).strip() for ln in v.splitlines()]
        return [p for p in parts if p]
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [str(v)]


def _as_text(v) -> str:
    """Coerce a model-supplied poc value to text (it may arrive as a list of lines)."""
    if isinstance(v, (list, tuple)):
        return "\n".join(str(x) for x in v)
    return str(v or "")


class _Operator:
    """One joseph run: holds the workspace, the live sessions, the ZAP handle, the scope, and the append-only
    run.jsonl. The litellm brain drives it; every turn's reasoning + actions + results are logged."""

    def __init__(self, args, provider, base_url: str, host: str, headers: list, zap):
        self.args = args
        self.provider = provider
        self.base_url = base_url
        self.host = host
        self.headers = headers                     # auth headers threaded into every tool call
        self.zap = zap
        self.real_tools = set(_real_tool_names())
        self.bases = scope.scope_bases(base_url)   # in-scope registrable domain(s); backends added as confirmed
        self.workspace = args.out_dir
        self.viewport = None
        self.debug = args.debug
        self._markers: dict = {}                   # per-identity flow-log cursor for session_read('flows')
        self._script_runs = 0
        self._script_lang: dict = {}               # script name -> language, so run_script needn't repeat it
        self.turns: list = []                      # provider narration sink (one record per model turn)
        self.findings: list = []                   # finding(...) calls, merged with the final JSON
        self.notes: list = []
        self.mutations: list = []                  # audit log of every mutating request (design §9)
        self._run_log = os.path.join(self.workspace, "run.jsonl")
        self._leads_log = os.path.join(self.workspace, "leads.jsonl")
        self._lock = threading.RLock()             # guards the append-only bus (driver + analyst threads, §17)
        self._leads_seen = 0                       # driver's cursor into leads.jsonl (leases new leads)
        self.stop = threading.Event()              # set at end so analyst threads wind down
        for sub in ("sessions", "flows", "scripts", "tools", "findings", "js"):
            os.makedirs(os.path.join(self.workspace, sub), exist_ok=True)

    # -- workspace / logging (the shared bus - lock-guarded, §17) ------------
    def _append_log(self, rec: dict) -> None:
        rec = {"ts": datetime.now(timezone.utc).isoformat(), **rec}
        with self._lock:
            try:
                with open(self._run_log, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, default=str) + "\n")
            except OSError:
                pass

    def add_lead(self, lane: str, detail: str, cls: str = "", url: str = "") -> None:
        """An analyst appends a candidate lead to the leads channel; the driver leases it later (§17)."""
        rec = {"ts": datetime.now(timezone.utc).isoformat(), "lane": lane, "detail": detail,
               "cls": cls, "url": url}
        with self._lock:
            try:
                with open(self._leads_log, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, default=str) + "\n")
            except OSError:
                pass

    def read_new_leads(self) -> list:
        """The leads appended since the driver last looked - the feedback edge the driver acts on (§17)."""
        with self._lock:
            if not os.path.exists(self._leads_log):
                return []
            try:
                with open(self._leads_log, encoding="utf-8") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                return []
            fresh = lines[self._leads_seen:]
            self._leads_seen = len(lines)
        out = []
        for ln in fresh:
            with contextlib.suppress(Exception):
                out.append(json.loads(ln))
        return out

    def _dump_session(self, identity: str | None) -> None:
        """Publish the held session's material to files on the bus (session material on disk): a script or an
        analyst reads sessions/<id>/{cookies.txt, localStorage.json, sessionStorage.json, storage.json}. Best-effort."""
        sid = self._sid(identity).replace(":", "_")
        page = cdp._SESSIONS.get(self._sid(identity))
        if page is None:
            return
        d = os.path.join(self.workspace, "sessions", sid)
        os.makedirs(d, exist_ok=True)
        with contextlib.suppress(Exception):
            with open(os.path.join(d, "cookies.txt"), "w", encoding="utf-8") as fh:
                fh.write(page.cookies() or "")
        store = {}
        with contextlib.suppress(Exception):
            store = page.storage_dump() or {}
        with contextlib.suppress(Exception):
            with open(os.path.join(d, "storage.json"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps(store, default=str, indent=2))
        for key, fname in (("localStorage", "localStorage.json"), ("sessionStorage", "sessionStorage.json")):
            if isinstance(store, dict) and key in store:
                with contextlib.suppress(Exception):
                    with open(os.path.join(d, fname), "w", encoding="utf-8") as fh:
                        fh.write(json.dumps(store[key], default=str, indent=2))

    def _save(self, subdir: str, name: str, content: str) -> str:
        path = os.path.join(self.workspace, subdir, name)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        except OSError as exc:  # noqa: BLE001
            return f"(could not write {path}: {exc})"
        return os.path.relpath(path, self.workspace)

    # -- scope / safety ------------------------------------------------------
    def _in_scope(self, url: str) -> bool:
        """In-scope = the target's registrable domain or a subdomain of it (design §9). A non-URL value is
        treated as in scope (it isn't an egress target)."""
        return scope.in_scope(url, self.bases)

    def _dry_run_blocks(self, method: str) -> bool:
        return bool(getattr(self.args, "dry_run", False)) and method.upper() in ("POST", "PUT", "PATCH", "DELETE")

    # -- the real-tool call (full registry, in-process, scope-guarded) -------
    def _call_tool(self, name: str, targs: dict) -> str:
        argv = toolschema.to_argv(name, targs)
        # scope-guard the egress target (the first positional URL, if any)
        for a in argv[1:]:
            if isinstance(a, str) and a.startswith(("http://", "https://")):
                if not self._in_scope(a):
                    return json.dumps({"success": False,
                                       "error": f"{a} is out of scope ({', '.join(self.bases) or 'target'}); "
                                                "joseph stays on the target + its own backends"})
                break
        # thread auth headers onto the tools that accept a --header flag (like bob)
        try:
            flag = toolschema.build(name)["flag_of"].get("header")
        except Exception:  # noqa: BLE001
            flag = None
        if flag and self.headers:
            argv = argv + [x for h in self.headers for x in (flag, h)]
        argv = agentlog.forward_debug(argv, self.debug)
        from ..cli import main as cli_main
        buf = io.StringIO()
        # serialize the in-process CLI call: its stdout redirect is a process-global swap, unsafe across the
        # driver + analyst threads (§17). Only the capture is locked; LLM turns still overlap.
        with _CLI_LOCK:
            try:
                with contextlib.redirect_stdout(buf):
                    cli_main(list(argv))
            except SystemExit:
                pass
            except Exception as exc:  # noqa: BLE001
                return json.dumps({"success": False, "error": f"{name} failed: {exc}"})
        out = buf.getvalue().strip()
        self._save("tools", f"{name}_{int(time.time() * 1000)}.json", out or "{}")
        if name == "http-request":
            self._archive_js(argv, out)             # keep the app's custom JS as readable source artifacts
        return out

    def _archive_js(self, argv: list, out: str) -> None:
        """When a fetch pulls a JS bundle (or its source map), save the RAW code to js/ as a clean artifact so
        analysts + scripts can read the app's custom code as source - that is where the hidden endpoints, DOM-XSS
        sinks and leaked config live. Best-effort; the JSON envelope is still in tools/."""
        url = next((a for a in argv[1:] if isinstance(a, str) and a.startswith("http")), "")
        path = urlparse(url).path.lower()
        if not path.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".js.map", ".map")):
            return
        try:
            item = (json.loads(out).get("data") or [{}])[0] or {}
            body = item.get("content") or ""
        except Exception:  # noqa: BLE001
            return
        if body:
            base = os.path.basename(path) or f"bundle_{int(time.time() * 1000)}.js"
            self._save("js", base, body)

    # -- live session --------------------------------------------------------
    def _sid(self, identity: str | None) -> str:
        return f"joseph:{(identity or 'A').upper()}"

    def _session(self, identity: str | None):
        proxy = self.zap.proxy if self.zap else None
        hdr = {}
        for h in self.headers:                     # carry auth headers into the browser too
            k, _, v = str(h).partition(":")
            if k and v:
                hdr[k.strip()] = v.strip()
        page, fresh = cdp.get_session(self._sid(identity), headers=hdr or None, timeout=self.args.timeout,
                                      debug=(debug_print if self.debug else (lambda _m: None)), proxy=proxy)
        return page

    def _session_open(self, a: dict) -> str:
        url = a.get("url", "")
        if url and not self._in_scope(url):
            return json.dumps({"error": f"{url} is out of scope"})
        try:
            page = self._session(a.get("identity"))
            status = page.navigate(url) if url else None
            self._markers[self._sid(a.get("identity"))] = page.flow_marker()
            self._dump_session(a.get("identity"))     # publish cookies/storage to the bus for scripts+analysts
            return json.dumps({"fresh": True, "status": status, "title": page.title(),
                               "url": page.current_url()}, default=str)
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"session_open failed: {exc}"})

    def _session_do(self, a: dict) -> str:
        steps = a.get("steps") or []
        if isinstance(steps, str):
            steps = [steps]
        sid = self._sid(a.get("identity"))
        try:
            page = self._session(a.get("identity"))
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"no live session: {exc}"})
        done = []
        for step in steps:
            verb, _, arg = str(step).partition(":")
            verb = verb.strip().lower()
            try:
                if verb == "navigate":
                    if arg and not self._in_scope(arg):
                        done.append(f"navigate:{arg} REFUSED (out of scope)")
                        continue
                    st = page.navigate(arg)
                    done.append(f"navigate -> {st}")
                elif verb == "click":
                    page.click(arg)
                    done.append(f"click {arg}")
                elif verb == "fill":
                    sel, _, val = arg.partition("=")
                    page.fill(sel, val)
                    done.append(f"fill {sel}")
                elif verb == "find":
                    hit = page.find_text(arg)
                    done.append(f"find {arg!r} -> {'present' if hit else 'absent'}")
                elif verb == "wait":
                    time.sleep(min(float(arg or 1), 10))
                    done.append(f"wait {arg}")
                else:
                    done.append(f"{verb}: unsupported verb")
            except Exception as exc:  # noqa: BLE001
                done.append(f"{verb} {arg}: error {exc}")
        # refresh the flow cursor so the next session_read('flows') shows what these steps produced
        with contextlib.suppress(Exception):
            self._markers[sid] = self._markers.get(sid, 0)
        return json.dumps({"did": done, "url": _safe(page.current_url)}, default=str)

    def _session_read(self, a: dict) -> str:
        what = (a.get("what") or "").lower()
        sid = self._sid(a.get("identity"))
        try:
            page = self._session(a.get("identity"))
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"no live session: {exc}"})
        try:
            if what == "flows":
                since = self._markers.get(sid, 0)
                flows = page.flows(since=since)
                self._markers[sid] = page.flow_marker()
                self._save("flows", f"flows_{int(time.time() * 1000)}.json", json.dumps(flows, default=str))
                return json.dumps(flows, default=str)
            if what == "requests":
                return json.dumps(page.request_summary(), default=str)
            if what == "dom":
                return page.content()
            if what == "storage":
                self._dump_session(a.get("identity"))
                return json.dumps(page.storage_dump(), default=str)
            if what == "cookies":
                self._dump_session(a.get("identity"))
                return page.cookies()
            if what == "form":
                return json.dumps(page.describe_form(), default=str)
            if what == "title":
                return page.title()
            if what == "url":
                return page.current_url()
            if what == "screenshot":
                shot = page.screenshot()
                name = f"shot_{int(time.time() * 1000)}.png"
                path = os.path.join(self.workspace, "flows", name)
                mode = "wb" if isinstance(shot, (bytes, bytearray)) else "w"
                with open(path, mode) as fh:
                    fh.write(shot)
                return json.dumps({"saved": os.path.relpath(path, self.workspace)})
            return json.dumps({"error": f"unknown read: {what}"})
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"session_read {what} failed: {exc}"})

    def _session_material(self, identity: str | None) -> tuple:
        """(cookie_header, bearer) for the held session, so a script can act as the logged-in user."""
        try:
            page = cdp._SESSIONS.get(self._sid(identity))
            if page is None:
                return "", ""
            cookie = ""
            with contextlib.suppress(Exception):
                cookie = page.cookies()
            bearer = ""
            with contextlib.suppress(Exception):
                for f in page.flows():
                    if f.get("req_auth"):
                        bearer = f["req_auth"]
                        break
            return cookie, bearer
        except Exception:  # noqa: BLE001
            return "", ""

    # -- scripting sandbox (the one genuinely new capability, design §8) -----
    def _write_script(self, a: dict) -> str:
        name = os.path.basename(a.get("name") or "")
        if not name:
            return json.dumps({"error": "a script name is required"})
        lang = (a.get("language") or "").lower()
        if lang:
            self._script_lang[name] = lang        # remember it so run_script runs it with the right interpreter
        rel = self._save("scripts", name, a.get("source") or "")
        return json.dumps({"written": rel})

    def _run_script(self, a: dict) -> str:
        if self._script_runs >= self.args.max_scripts:
            return json.dumps({"error": f"script budget exhausted (--max-scripts {self.args.max_scripts})"})
        name = os.path.basename(a.get("name") or "")
        path = os.path.join(self.workspace, "scripts", name)
        if not os.path.exists(path):
            return json.dumps({"error": f"no such script (write_script first): {name}"})
        self._script_runs += 1
        timeout = min(int(a.get("timeout") or self.args.script_timeout), self.args.script_timeout)
        cookie, bearer = self._session_material(None)
        env = {**os.environ,
               "JOSEPH_TARGET": self.base_url, "JOSEPH_HOST": self.host,
               "JOSEPH_WORKSPACE": self.workspace,
               "JOSEPH_COOKIE": cookie or "", "JOSEPH_BEARER": bearer or ""}
        if self.zap:
            env["HTTP_PROXY"] = env["HTTPS_PROXY"] = self.zap.proxy
            if self.zap.ca_file:
                env["REQUESTS_CA_BUNDLE"] = self.zap.ca_file
        # language is remembered from write_script (else inferred from the extension, else python), so the model
        # need not repeat it here. python | shell | node.
        lang = (a.get("language") or self._script_lang.get(name) or _lang_from_ext(name) or "python").lower()
        interp = {"python": [sys.executable], "shell": ["bash"], "sh": ["bash"], "bash": ["bash"],
                  "node": ["node"], "javascript": ["node"], "js": ["node"]}.get(lang, [sys.executable])
        argv = interp + [path] + [str(x) for x in (a.get("args") or [])]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                  env=env, cwd=self.workspace)  # noqa: S603 - operator sandbox in-container
            out = {"exit": proc.returncode, "stdout": _cap(proc.stdout, 20000),
                   "stderr": _cap(proc.stderr, 8000)}
        except subprocess.TimeoutExpired:
            out = {"exit": None, "error": f"script timed out after {timeout}s"}
        except Exception as exc:  # noqa: BLE001
            out = {"exit": None, "error": f"script failed to launch: {exc}"}
        self._save("scripts", name + ".out.json", json.dumps(out, default=str))
        return json.dumps(out, default=str)

    # -- mutate + replay through ZAP -----------------------------------------
    def _mutate_replay(self, a: dict) -> str:
        url = a.get("url", "")
        method = (a.get("method") or "GET").upper()
        if not url or not self._in_scope(url):
            return json.dumps({"error": f"{url or '(no url)'} is out of scope or missing"})
        if self._dry_run_blocks(method):
            return json.dumps({"error": f"--dry-run: {method} refused; map and predict instead"})
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            self.mutations.append({"ts": time.time(), "method": method, "url": url})
            self._append_log({"kind": "mutation", "method": method, "url": url})
        # route through http-request (target/method/data/header dests). It honours HTTP(S)_PROXY (set for the
        # run when ZAP is up), so the edited replay is captured in the same store as everything else (§6).
        targs: dict = {"target": url, "method": method}
        if a.get("body"):
            targs["data"] = a["body"]
        if a.get("headers"):
            targs["header"] = [str(h) for h in a["headers"]]
        return self._call_tool("http-request", targs)

    # -- notes / findings ----------------------------------------------------
    def _note(self, a: dict) -> str:
        rec = {"kind": a.get("kind", "lead"), "detail": a.get("detail", "")}
        self.notes.append(rec)
        self._append_log({"kind": "note", **rec})
        return json.dumps({"noted": True})

    def _finding(self, a: dict) -> str:
        f = {"severity": str(a.get("severity", "info")).lower(), "title": a.get("title", ""),
             "url": a.get("url", ""), "cls": a.get("cls", ""),
             "summary": a.get("summary", ""), "steps": _as_list(a.get("steps")),
             "poc": _as_text(a.get("poc")), "impact": a.get("impact", ""),
             "remediation": _as_list(a.get("remediation")),
             "predicted_observable": a.get("predicted_observable", ""), "evidence": a.get("evidence", "")}
        self.findings.append(f)
        self._save("findings", f"finding_{len(self.findings)}.json", json.dumps(f, default=str))
        self._append_log({"kind": "finding", **f})
        return json.dumps({"recorded": True, "count": len(self.findings)})

    def _workspace_read(self, a: dict) -> str:
        path = os.path.normpath(os.path.join(self.workspace, a.get("path", "")))
        if not path.startswith(os.path.normpath(self.workspace)):
            return json.dumps({"error": "path escapes the workspace"})
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return _cap(fh.read())
        except OSError as exc:
            return json.dumps({"error": str(exc)})

    def _workspace_list(self, a: dict) -> str:
        import glob as _glob
        pat = a.get("glob") or "**/*"
        hits = _glob.glob(os.path.join(self.workspace, pat), recursive=True)
        return json.dumps([os.path.relpath(h, self.workspace) for h in hits if os.path.isfile(h)][:500])

    def _load_skill(self, a: dict) -> str:
        """Hand the driver a vuln-class PLAYBOOK on demand (the ai/skills/*.md knowledge). Emits a `joseph ::`
        line so the load shows in the run stream, and records it in run.jsonl."""
        name = (a.get("name") or "").strip()
        body = skills.load(name)
        if not body:
            return json.dumps({"error": f"no such skill: {name!r}",
                               "available": [n for n, _ in skills.catalog()]})
        self._append_log({"kind": "skill_loaded", "who": "driver", "name": name})
        sys.stderr.write(f"joseph :: [driver] loaded playbook: {name}\n")
        return _cap(body)

    # -- dispatch ------------------------------------------------------------
    def dispatch(self, name: str, targs: dict) -> str:
        if name in self.real_tools:
            return self._call_tool(name, targs)
        handler = {
            "session_open": self._session_open, "session_do": self._session_do,
            "session_read": self._session_read, "write_script": self._write_script,
            "run_script": self._run_script, "mutate_replay": self._mutate_replay,
            "workspace_read": self._workspace_read, "workspace_list": self._workspace_list,
            "load_skill": self._load_skill,
            "note": self._note, "finding": self._finding,
        }.get(name)
        if handler is None:
            return json.dumps({"error": f"{name} is not a joseph action"})
        return handler(targs or {})


def _lang_from_ext(name: str) -> str:
    """Best-effort script language from the file extension - the fallback when write_script's language wasn't
    recorded (so a shell/node script is never mis-run under python)."""
    ext = os.path.splitext(name or "")[1].lower()
    return {".py": "python", ".sh": "shell", ".bash": "shell",
            ".js": "node", ".mjs": "node", ".cjs": "node"}.get(ext, "")


def _safe(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return ""


def _all_tool_specs() -> list:
    """The full action list handed to the DRIVER model: real tools (native schemas) + session + meta actions."""
    return toolschema.native_tools(_real_tool_names()) + _SESSION_ACTIONS + _META_ACTIONS


# -- the read-only ANALYST (a parallel consumer on the bus, design §17) --------------------------------------
_LEAD_ACTION = {
    "name": "lead",
    "description": "Append a candidate lead to the shared bus for the DRIVER to lease and test live. Give the "
                   "EXACT endpoint / param / vector and WHY it is worth active testing.",
    "schema": {"type": "object", "additionalProperties": False,
               "properties": {"detail": {"type": "string"},
                              "cls": {"type": "string", "description": "vuln class, e.g. xss / idor / sqli"},
                              "url": {"type": "string"}},
               "required": ["detail"]},
}

_ANALYST_SYSTEM = (
    "You are a READ-ONLY ANALYST on joseph's team - {brief}\n\n"
    "You do NOT drive the live browser and you do NOT issue destructive / mutating requests (no session "
    "writes, no mutate_replay, no mass-assign - those stay with the DRIVER). But you MAY use EVERY "
    "non-destructive tool in your lane - the discovery tools AND the scanners fuzz / sqlmap / nuclei / "
    "bola-walk / blind-oracle - to CONFIRM, not just flag. You CONSUME the shared workspace BUS: "
    "workspace_list to see what the driver has published, workspace_read to read a flow / DOM snapshot / tool "
    "output / session-material file (sessions/<id>/localStorage.json, cookies.txt, ...). "
    "THINK OUT LOUD every turn - observe (the exact string/value) -> interpret (vs. a baseline) -> trace (how "
    "a value flows) -> hypothesize (a checkable claim) -> plan - exactly like the driver. When you spot "
    "something worth active testing, call lead(detail, cls, url) with the exact vector and WHY; the driver "
    "leases your leads, tests them live, and its new observations come back to you on the bus. Stay strictly "
    "in scope. Your step budget is small - find the highest-value leads in your lane, don't be exhaustive. "
    "When your lane is exhausted, stop (reply with no tool call)."
)


def _readonly_args(name: str, targs: dict) -> dict:
    """Force an analyst tool call to stay read-only - strip anything that would make http-request mutate."""
    targs = dict(targs or {})
    if name == "http-request":
        targs.pop("data", None)
        targs.pop("method", None)
    return targs


def _analyst_specs() -> list:
    meta = [m for m in _META_ACTIONS if m["name"] in ("workspace_read", "workspace_list")]
    return toolschema.native_tools(_ANALYST_TOOLS) + meta + [_LEAD_ACTION]


def _run_analyst(op: "_Operator", provider, lane: str, brief: str, brief_user: str, max_steps: int) -> None:
    """One read-only analyst loop: consume the bus, reason out loud, emit leads. Runs in its own thread; only
    the DRIVER mutates sessions, so this is safe against the live browser (it reads published snapshots)."""
    specs = _analyst_specs()
    system = _ANALYST_SYSTEM.format(brief=brief)
    # PRELOAD this lane's vuln-class playbook(s) (ai/skills/*.md) so the analyst carries the deep methodology of
    # its class, not just the one-line brief. A `joseph ::` line records the load in the run stream (§16).
    loaded, kb = [], []
    for sname in _LANE_SKILLS.get(lane, []):
        body = skills.load(sname)
        if body:
            loaded.append(sname)
            kb.append(f"## {sname}\n\n{body}")
    if kb:
        system += ("\n\n# LANE KNOWLEDGE - the deep PLAYBOOK(s) for your class (exact payloads, steps, "
                   "confirmation markers, gotchas). Follow the one(s) that apply to what you observe on the "
                   "bus:\n\n" + "\n\n---\n\n".join(kb))
        op._append_log({"kind": "skill_loaded", "who": lane, "name": ",".join(loaded)})
        sys.stderr.write(f"joseph :: [{lane}] loaded playbook(s): {', '.join(loaded)}\n")
    messages = [{"role": "user", "content": brief_user + "\n\nStart by listing the bus (workspace_list), read "
                 "what is relevant to your lane, and emit leads as you find them. Begin."}]
    for _ in range(max(1, max_steps)):
        if op.stop.is_set():
            return
        try:
            resp = provider.send(system, messages, specs)
        except Exception:  # noqa: BLE001 - an analyst dying must never take down the run
            return
        prev = len(provider.sink or [])
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        turn = provider.sink[-1] if provider.sink and len(provider.sink) > prev \
            else {"reasoning": "", "narration": text}
        op._append_log({"kind": "analyst", "lane": lane, "reasoning": turn.get("reasoning", ""),
                        "narration": turn.get("narration", ""), "actions": [c["name"] for c in calls]})
        if not calls:
            return
        results = []
        for c in calls:
            name, targs = c["name"], c.get("args", {})
            if op.stop.is_set():
                return
            if name == "lead":
                op.add_lead(lane, targs.get("detail", ""), targs.get("cls", ""), targs.get("url", ""))
                out = json.dumps({"lead_recorded": True})
            elif name in ("workspace_read", "workspace_list"):
                out = op.dispatch(name, targs)
            elif name in _ANALYST_TOOLS:
                out = op._call_tool(name, _readonly_args(name, targs))
            else:
                out = json.dumps({"error": f"{name} is not allowed for a read-only analyst"})
            results.append({"id": c["id"], "output": _cap(out)})
        messages += provider.tool_results(results)


# -- the AUTH agent (a dedicated login role, design §5) ------------------------------------------------------
_AUTH_SYSTEM = (
    "You are the AUTH agent on joseph's team. Your ONE job: LOG IN via the live browser and hand a working "
    "authenticated session to the driver. You are the SOLE writer to the session while you work (the driver "
    "waits for you), so there is no conflict. Method: session_open the login page; session_read 'form' to see "
    "the REAL field selectors (observe, don't assume names); session_do 'fill:<selector>=<value>' for the "
    "username then the password, then 'click:<submit-selector>'; session_read 'url' and 'flows' to CONFIRM you "
    "are authenticated - you landed on an app/dashboard page or an authed request returned your data, NOT the "
    "login form again or a redirect back to login. If it fails, read why and adapt (wrong selector, a hidden "
    "CSRF field, a two-step or SSO form). When identity A is confirmed in, repeat for identity B if one was "
    "given (use identity 'B' in the actions). THINK OUT LOUD each step. When done - or if you truly cannot log "
    "in - stop with NO action and one line stating whether A (and B) are authenticated.")

_AUTH_ACTIONS = _SESSION_ACTIONS + [m for m in _META_ACTIONS if m["name"] == "note"]
_AUTH_ALLOWED = {"session_open", "session_do", "session_read", "note"}


def _run_auth(op: "_Operator", provider, creds: str, creds_b: str | None, login_url: str,
              max_steps: int = 20) -> None:
    """Establish the authenticated live session(s) BEFORE the driver's main loop - a dedicated login agent that
    drives the real browser (the human way), then publishes A's session material as the tools' auth headers so
    every subsequent tool call / analyst / script runs authenticated. Respects one-writer: it finishes before
    the driver begins, so only one agent ever mutates the session (design §5/§17)."""
    creds_lines = [f"Identity A credentials: {creds}"]
    if creds_b:
        creds_lines.append(f"Identity B credentials: {creds_b}")
    user = ("Log the live browser in now.\nLOGIN URL: " + login_url + "\n" + "\n".join(creds_lines)
            + "\nUse identity 'A' for the first pair and 'B' for the second. Confirm each session is "
              "authenticated, then stop.")
    messages = [{"role": "user", "content": user}]
    for _ in range(max(1, max_steps)):
        try:
            resp = provider.send(_AUTH_SYSTEM, messages, _AUTH_ACTIONS)
        except Exception:  # noqa: BLE001 - a failed login must not crash the run; driver proceeds anon
            break
        prev = len(provider.sink or [])
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        turn = provider.sink[-1] if provider.sink and len(provider.sink) > prev \
            else {"reasoning": "", "narration": text}
        op._append_log({"kind": "auth", "reasoning": turn.get("reasoning", ""),
                        "narration": turn.get("narration", ""), "actions": [c["name"] for c in calls]})
        if not calls:
            break
        results = []
        for c in calls:
            name, targs = c["name"], c.get("args", {})
            out = op.dispatch(name, targs) if name in _AUTH_ALLOWED \
                else json.dumps({"error": f"{name} is not an auth-agent action"})
            results.append({"id": c["id"], "output": _cap(out)})
        messages += provider.tool_results(results)
    # hand identity A's established session material to the TOOL layer so http-request / analysts / scripts run
    # authenticated (the live browser holds cookies; tools need them as headers).
    cookie, bearer = op._session_material("A")
    if cookie and not any("cookie:" in h.lower() for h in op.headers):
        op.headers.append(f"Cookie: {cookie}")
    if bearer and not any(h.lower().startswith("authorization:") for h in op.headers):
        op.headers.append(f"Authorization: {bearer}")
    op._dump_session("A")
    if creds_b:
        op._dump_session("B")


def _rich_finding_block(f: dict) -> list[str]:
    """One finding rendered as a professional pentest / bug-bounty writeup: a metadata line (class/CWE/CVSS/url),
    then Summary -> Steps to reproduce -> Proof of concept -> Impact -> Remediation -> Evidence. Text is run
    through forge.mask so a live-looking secret is never reprinted; CWE + the CVSS heuristic come from
    forge.enrich (called by the caller before this)."""
    sev = str(f.get("severity", "info")).capitalize()
    out = [f"### [{sev}] {f.get('title', '')}", ""]
    meta = [f"- **Class / CWE:** {f.get('class', 'other')} / {f.get('cwe', 'CWE-Other')}",
            f"- **CVSS 3.1 (heuristic):** {f.get('cvss', '?')} `{f.get('cvss_vector', '')}`"]
    if f.get("url"):
        meta.append(f"- **URL:** {f['url']}")
    if f.get("predicted_observable"):
        meta.append(f"- **Validation:** confirmed - predicted `{fr.mask(str(f['predicted_observable']))}`, "
                    "observed in the evidence below")
    out += meta + [""]
    if f.get("summary"):
        out += [f"**Summary.** {fr.mask(str(f['summary']))}", ""]
    steps = _as_list(f.get("steps"))
    if steps:
        out += ["**Steps to reproduce.**", ""]
        out += [f"{i}. {fr.mask(s)}" for i, s in enumerate(steps, 1)] + [""]
    poc = _as_text(f.get("poc"))
    if poc.strip():
        out += ["**Proof of concept.**", "", "```", fr.mask(poc.strip()), "```", ""]
    if f.get("impact"):
        out += [f"**Impact.** {fr.mask(str(f['impact']))}", ""]
    remediation = _as_list(f.get("remediation"))
    if remediation:
        out += ["**Remediation.**", ""] + [f"- {fr.mask(r)}" for r in remediation] + [""]
    if f.get("evidence"):
        out += [f"**Evidence.** {fr.mask(str(f['evidence']))}", ""]
    return out


def _usage_report_lines(cost: float, tot: dict) -> list[str]:
    """The token-spend section of the report: exact token counts + a dollar cost, broken down per model. The
    tokens are always exact (from each response's usage). The cost is EXACT too when the gateway reported it
    (cost_source == 'gateway'); otherwise it's a list-price estimate the reader can override via env."""
    exact = tot.get("cost_source") == "gateway"
    cost_note = ("gateway-reported, exact" if exact else
                 "list-price estimate; set BOXCUTTER_PRICE_IN / BOXCUTTER_PRICE_OUT - USD per 1M tokens - "
                 "for your exact gateway/Bedrock rate")
    lines = ["## Token usage & cost", "",
             f"- LLM calls: {tot.get('calls', 0)}",
             f"- input: {tot.get('prompt_tokens', 0):,} tok   output: {tot.get('completion_tokens', 0):,} tok   "
             f"total: {tot.get('total_tokens', 0):,} tok",
             f"- {'cost' if exact else 'estimated cost'}: **${cost:,.4f} USD** _({cost_note})_", ""]
    by_model = tot.get("by_model") or {}
    if by_model:
        lines += ["| model | calls | input tok | output tok |", "|---|---:|---:|---:|"]
        lines += [f"| {m} | {u.get('calls', 0)} | {u.get('prompt_tokens', 0):,} | {u.get('completion_tokens', 0):,} |"
                  for m, u in by_model.items()]
        lines.append("")
    return lines


def _render_report(op: _Operator, base_url: str, data: dict, findings: list) -> str:
    sev: dict = {}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        sev[s] = sev.get(s, 0) + 1
    app = data.get("application", {}) if isinstance(data, dict) else {}
    lines = [f"# joseph report - {base_url}", "",
             f"- findings: {len(findings)}  by severity: {sev or '{}'}",
             f"- mutations performed: {len(op.mutations)}   scripts run: {op._script_runs}",
             f"- workspace: {op.workspace}", ""]
    if app:
        lines += ["## Application", "",
                  f"- **what**: {app.get('description', '')}", f"- **stack**: {app.get('stack', '')}",
                  f"- **api**: {app.get('api', '')}", f"- **auth**: {app.get('auth', '')}", ""]
    # THE INVESTIGATION NARRATIVE - joseph's headline deliverable (design §16): the story of the session,
    # reconstructed from the model's own closing narrative plus the reasoning stream in run.jsonl.
    lines += ["## Investigation (the reasoning stream)", ""]
    if isinstance(data, dict) and data.get("investigation"):
        lines += [data["investigation"], ""]
    lines.append("_Full turn-by-turn thinking + actions: `run.jsonl`._")
    lines.append("")
    # enrich every finding with class -> CWE + a CVSS 3.1 heuristic, then render each as a full writeup. forge's
    # class_of reads f["class"]; joseph findings carry the class as `cls`, so map it across first (design §12).
    for f in findings:
        if not f.get("class") and f.get("cls"):
            f["class"] = f["cls"]
    fr.enrich(findings)
    lines += ["## Findings", ""]
    if not findings:
        lines.append("_None survived the validation gate._")
        lines.append("")
    for f in findings:
        lines += _rich_finding_block(f)
    if op.notes:
        lines += ["## Open leads (unproven - notes)", ""]
        lines += [f"- ({n.get('kind', 'lead')}) {n.get('detail', '')}" for n in op.notes]
        lines.append("")
    # leads the parallel analyst lanes posted to the bus (the cooperation output, §17)
    bus_leads = []
    if os.path.exists(op._leads_log):
        with contextlib.suppress(Exception):
            with open(op._leads_log, encoding="utf-8") as fh:
                bus_leads = [json.loads(x) for x in fh.read().splitlines() if x.strip()]
    if bus_leads:
        lines += [f"## Analyst leads ({len(bus_leads)} from the parallel read-only lanes)", ""]
        lines += [f"- [{ld.get('lane', '?')}] {ld.get('cls', '')} {ld.get('url', '')}: {ld.get('detail', '')}"
                  for ld in bus_leads]
        lines.append("")
    if isinstance(data, dict):
        lines += ["## Coverage", "", data.get("coverage", ""), "",
                  "## Bottom line", "", data.get("bottom_line", ""), ""]
    return "\n".join(lines)


def add_arguments(parser) -> None:
    # joseph is GOAL-DIRECTED: its primary input is the --context BRIEF (the goal, the endpoints, and the
    # authentication), not a bare URL. A positional target is OPTIONAL - if omitted, the app root and scope
    # are derived from the endpoints named in --context.
    parser.add_argument("target", nargs="?", default=None,
                        help="Optional app root URL. Usually omitted - joseph reads the goal, endpoints and "
                             "auth from --context and derives the target/scope from the endpoints there.")
    parser.add_argument("--analysts", type=int, default=len(_ANALYST_LANES), metavar="N",
                        help="Parallel read-only analyst agents to run alongside the driver (default: all "
                             "lanes). 0 = single-operator, no analysts. They cooperate via the shared bus.")
    parser.add_argument("--analyst-steps", dest="analyst_steps", type=int, default=40,
                        help="Per-analyst step budget")
    parser.add_argument("--creds", default=None, metavar="USER:PASS",
                        help="Identity A credentials for a live-browser login (via session_do or --context)")
    parser.add_argument("--creds-b", dest="creds_b", default=None, metavar="USER:PASS",
                        help="Optional identity B for differential (two-account BOLA/BFLA)")
    parser.add_argument("--login-url", dest="login_url", default=None, help="Login page URL (default: target)")
    parser.add_argument("--out-dir", dest="out_dir", default=None, metavar="DIR",
                        help="Run workspace folder (default: joseph_<host>_<ts>)")
    parser.add_argument("--max-rounds", dest="max_rounds", type=int, default=6,
                        help="Replan rounds (soft budget; --max-steps is the hard cap)")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true",
                        help="Map and predict only; refuse all mutation (POST/PUT/PATCH/DELETE)")
    parser.add_argument("--quiet-reasoning", dest="quiet_reasoning", action="store_true",
                        help="Do not stream the reasoning narrative live (it is still persisted to run.jsonl)")
    parser.add_argument("--max-scripts", dest="max_scripts", type=int, default=25,
                        help="Cap on write_script/run_script executions per run")
    parser.add_argument("--script-timeout", dest="script_timeout", type=int, default=120,
                        help="Per-script wall-clock timeout (seconds)")
    parser.add_argument("--timeout", type=int, default=45, help="Per-navigation/browser timeout (seconds)")
    add_agent_args(parser, max_steps=400)


def run(args) -> int:
    # GOAL-DIRECTED input: the primary input is the --context brief (goal + endpoints + auth). A positional
    # target is optional; when omitted, derive the app root and scope from the endpoints named in the brief.
    context = (args.context or "").strip()
    target = (args.target or "").strip()
    urls_in_ctx = re.findall(r'https?://[^\s"\'<>)\]]+', context)
    if not target and urls_in_ctx:
        target = urls_in_ctx[0]
    if not target:
        output_result([], args.output,
                      "joseph needs a target - give one, or describe the goal + endpoints in --context")
        return 2
    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    host = (urlparse(base_url).hostname or "").lower()

    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key and getattr(provider_cls, "requires_key", True):
        sys.stderr.write(f"joseph: an LLM is required - provide --api-key or set {provider_cls.env} "
                         f"for --provider {args.provider}\n")
        return 2

    if not args.out_dir:
        args.out_dir = f"joseph_{host or 'target'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(args.out_dir, exist_ok=True)

    reset_usage()   # fresh token ledger for THIS run - every provider (driver/auth/analysts) accumulates into it

    provider = make_provider(args.provider, args.model, key, base_url=args.base_url,
                             reasoning=getattr(args, "reasoning", 0))

    headers = list(args.header or [])
    if args.context.strip():
        cfg = briefing.parse(provider, args.context, host)
        headers += cfg.get("headers", []) or []
        if cfg.get("headers"):
            sys.stderr.write("joseph :: auth header(s) parsed from --context (values hidden)\n")

    # ONE traffic sink: start ZAP once, point the tools + scripts + browser at it. None => cdp in-process
    # capture only (a graceful fallback, not a hard dependency; design §6).
    dbg = debug_print if args.debug else (lambda _m: None)
    zap = _zapproxy.start(dbg)
    saved_env = {k: os.environ.get(k) for k in ("HTTP_PROXY", "HTTPS_PROXY", "REQUESTS_CA_BUNDLE", "NO_PROXY")}
    if zap:
        os.environ["HTTP_PROXY"] = os.environ["HTTPS_PROXY"] = zap.proxy
        if zap.ca_file:
            os.environ["REQUESTS_CA_BUNDLE"] = zap.ca_file
        # keep the LLM gateway + the ZAP API itself OFF the proxy (never MITM our own control plane)
        llm_host = (urlparse(args.base_url).hostname if args.base_url else "") or ""
        os.environ["NO_PROXY"] = ",".join(x for x in ("127.0.0.1", "localhost", llm_host) if x)
        sys.stderr.write(f"joseph :: ZAP capture up on {zap.proxy}\n")

    op = _Operator(args, provider, base_url, host, headers, zap)
    # scope = the target's registrable domain PLUS every host named in the brief's endpoints (a goal often
    # spans a UI host + an api. backend). Third-party hosts stay out (§9).
    for u in urls_in_ctx:
        b = scope.registrable_domain(u)
        if b and b not in op.bases:
            op.bases.append(b)
    # WIRE THE REASONING STREAM (design §16): the provider captures {reasoning, narration, calls} per turn into
    # op.turns; stream it live unless --quiet-reasoning. This is joseph's headline deliverable.
    provider.sink = op.turns
    provider.label = "joseph:driver"
    provider.stream = not args.quiet_reasoning

    # The shared MISSION BRIEF: goal + endpoints + auth from --context, plus derived target/scope/workspace.
    # Both the driver and every analyst start from it (they diverge on role/lane).
    brief_user = (
        "MISSION BRIEF (from --context - your GOAL, the ENDPOINTS in play, and how to AUTHENTICATE):\n"
        f"{context or '(no context given - infer the goal from the target)'}\n\n"
        f"DERIVED TARGET: {base_url}\n"
        f"SCOPE: {', '.join(op.bases) or host} (the target + the API/backend hosts named in the brief; stay "
        "off unrelated third-party hosts).\n"
        f"WORKSPACE: {op.workspace} (the shared BUS - everything you and the analysts gather lands here; read "
        "it back with workspace_list / workspace_read).\n"
        + ("MODE: --dry-run (map + predict only, do NOT mutate).\n" if args.dry_run else "")
        + "\n" + _WORDLISTS_ON_DISK)

    # AUTH agent (design §5): when creds are given, a dedicated login agent drives the real browser to log in
    # and publishes identity A's material as the tools' auth headers - BEFORE anyone else runs. It is the sole
    # session writer during login, so the one-writer rule holds and everything downstream runs authenticated.
    login_url = args.login_url or base_url
    if args.creds:
        authp = make_provider(args.provider, args.model, key, base_url=args.base_url,
                              reasoning=getattr(args, "reasoning", 0))
        authp.sink, authp.label, authp.stream = [], "joseph:auth", not args.quiet_reasoning
        sys.stderr.write("joseph :: auth agent logging in (identity A"
                         + (", B" if args.creds_b else "") + ") ...\n")
        _run_auth(op, authp, args.creds, args.creds_b, login_url)

    # SPAWN THE PARALLEL ANALYSTS (design §17): read-only consumers on the bus, one per lane, cooperating with
    # the driver through leads. Each gets its own provider (sink/label/stream) so its thinking streams under
    # its own lane name. They are daemon threads, step-bounded, and only ever READ the live resource's snapshots.
    n_analysts = max(0, min(int(getattr(args, "analysts", 0) or 0), len(_ANALYST_LANES)))
    threads = []
    for lane, brief in _ANALYST_LANES[:n_analysts]:
        aprov = make_provider(args.provider, args.model, key, base_url=args.base_url,
                              reasoning=getattr(args, "reasoning", 0))
        aprov.sink = []
        aprov.label = f"joseph:{lane}"
        aprov.stream = not args.quiet_reasoning
        t = threading.Thread(target=_run_analyst, name=f"joseph-analyst-{lane}",
                             args=(op, aprov, lane, brief, brief_user, args.analyst_steps), daemon=True)
        threads.append(t)
    if threads:
        sys.stderr.write(f"joseph :: spawning {len(threads)} parallel analyst(s): "
                         f"{', '.join(l for l, _ in _ANALYST_LANES[:n_analysts])}\n")
        for t in threads:
            t.start()

    driver_user = (brief_user + "\nYou are the DRIVER (the sole writer to the live session). Open the app in "
                   "your browser, watch its traffic, and work toward the GOAL. The analysts are reading the "
                   "bus in parallel and will post LEADS - lease the promising ones and test them live.\n"
                   "PLAYBOOKS you can load_skill(name) for the deep methodology of a class: "
                   + ", ".join(n for n, _ in skills.catalog()) + ".\n"
                   "THINK OUT LOUD every turn (observe -> interpret -> trace -> hypothesize -> plan) before you "
                   "act. Begin.")
    tools_spec = _all_tool_specs()
    messages = [{"role": "user", "content": driver_user}]

    final_text = ""
    count: dict = {}
    step = 0
    try:
        for step in range(max(1, args.max_steps)):
            # feedback edge: fold in any leads the analysts posted since last round, for the driver to lease.
            leads = op.read_new_leads()
            if leads:
                summary = "\n".join(
                    f"- [{ld.get('lane', '?')}] {ld.get('cls', '')} {ld.get('url', '')}: {ld.get('detail', '')}"
                    for ld in leads[:20])
                messages.append({"role": "user", "content": "ANALYSTS POSTED NEW LEADS on the bus - evaluate "
                                 "and lease the promising ones (test them live, in-session):\n" + summary})
            try:
                resp = provider.send(_SYSTEM, messages, tools_spec)
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write(f"joseph: provider error: {exc}\n")
                break
            prev = len(op.turns)
            text, calls = provider.parse(resp)
            messages += provider.assistant_msg(resp)
            turn = op.turns[-1] if len(op.turns) > prev else {"narration": text, "reasoning": "", "calls": []}
            if text.strip():
                final_text = text

            if not calls:
                if final_text.strip() and ("```json" in final_text or '"findings"' in final_text):
                    op._append_log({"kind": "turn", "step": step, "reasoning": turn.get("reasoning", ""),
                                    "narration": turn.get("narration", ""), "actions": [], "results": []})
                    break
                messages.append({"role": "user", "content": "Keep going - act through the tools/session/scripts. "
                                 "Narrate your observe->interpret->trace->hypothesize->plan first, then act."})
                op._append_log({"kind": "turn", "step": step, "reasoning": turn.get("reasoning", ""),
                                "narration": turn.get("narration", ""), "actions": [], "results": [],
                                "nudged": True})
                continue

            results, actions = [], []
            for c in calls:
                argv_key = json.dumps([c["name"], c.get("args", {})], sort_keys=True, default=str)
                count[argv_key] = count.get(argv_key, 0) + 1
                if count[argv_key] > 2:
                    out = json.dumps({"success": False, "error": "already ran this exact call - reuse the result"})
                else:
                    if args.debug:
                        debug_print("joseph> " + c["name"] + " " + json.dumps(c.get("args", {}), default=str)[:200])
                    out = op.dispatch(c["name"], c.get("args", {}))
                results.append({"id": c["id"], "output": _cap(out)})
                actions.append({"name": c["name"], "args": c.get("args", {})})
            messages += provider.tool_results(results)

            # THE TRACE + THINKING STREAM: one run.jsonl record per turn (reasoning + narration + actions + a
            # digest of each result). This is both the replay guarantee and the "show me what it did & why".
            op._append_log({"kind": "turn", "step": step,
                            "reasoning": turn.get("reasoning", ""), "narration": turn.get("narration", ""),
                            "actions": actions,
                            "results": [{"name": a["name"], "digest": _digest(r["output"])}
                                        for a, r in zip(actions, results)]})
    finally:
        op.stop.set()                              # tell the analysts to wind down
        for t in threads:                          # they are step-bounded + daemon; join briefly, don't hang
            with contextlib.suppress(Exception):
                t.join(timeout=10)
        cdp.close_all_sessions()
        _zapproxy.shutdown(zap)
        for k, v in saved_env.items():             # restore the proxy env we borrowed
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # merge the model's final-JSON findings with those recorded via finding() during the run
    data, json_findings = {}, []
    parsed = extract_json(final_text) if final_text else None
    if isinstance(parsed, dict):
        data = parsed
        json_findings = [f for f in (parsed.get("findings") or []) if isinstance(f, dict)]
        for f in json_findings:
            f["severity"] = str(f.get("severity", "info")).lower()
    findings = _merge_findings(op.findings, json_findings)

    # TOKEN SPEND: exact token counts (from each API response's usage block) + an estimated dollar cost. Printed
    # to stderr always (not just under --debug) and folded into the report + the result envelope.
    cost, tot = usage_cost()
    report = _render_report(op, base_url, data, findings)
    report += "\n" + "\n".join(_usage_report_lines(cost, tot))
    op._save(".", "REPORT.md", report)
    debug_print(f"\njoseph :: {len(findings)} finding(s), {op._script_runs} script(s), "
                f"{len(op.mutations)} mutation(s)  ({step + 1} steps)")
    _exact = tot.get("cost_source") == "gateway"
    _cost_tag = ("gateway-reported" if _exact else
                 "estimate; set BOXCUTTER_PRICE_IN/OUT for your exact gateway rate")
    sys.stderr.write(
        f"joseph :: LLM spend - {tot['prompt_tokens']:,} in + {tot['completion_tokens']:,} out = "
        f"{tot['total_tokens']:,} tokens over {tot['calls']} call(s)  "
        f"{'' if _exact else '~'}${cost:,.4f} USD ({_cost_tag})\n")
    if getattr(args, "report", None):
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
        except OSError as exc:
            sys.stderr.write(f"joseph: could not write report to {args.report}: {exc}\n")

    extra = {"target": base_url, "report": report, "workspace": op.workspace,
             "mutations": len(op.mutations), "scripts": op._script_runs, "steps": step + 1,
             "tokens": tot, "cost_usd": cost}
    # The human REPORT is the deliverable, so put it CLEARLY in the output. In table/human mode print the full
    # report to STDOUT (after the findings table); in JSON mode keep stdout as the clean machine envelope (the
    # report still rides in extra["report"]) and echo the report to stderr so it stays visible.
    human_stdout = bool(getattr(args, "table", False))
    if not human_stdout:
        debug_print(report + "\n")
    output_result(findings, args.output, extra=extra)
    if human_stdout:
        sys.stdout.write("\n" + report + "\n")
        sys.stdout.flush()
    return 0


def _merge_findings(primary: list, extra: list) -> list:
    """Dedup findings on (severity,title,url); finding() calls win over the final-JSON summary."""
    out, seen = [], set()
    for f in list(primary) + list(extra):
        key = (str(f.get("severity", "")).lower(), (f.get("title") or "").strip().lower(),
               (f.get("url") or "").strip().lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out

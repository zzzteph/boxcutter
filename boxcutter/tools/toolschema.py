"""Machine-readable, argparse-derived tool schemas - the single source of truth for what each boxcutter
sub-command accepts, for any agentic caller that wants to hand its LLM provider NATIVE function-calling
tools instead of hand-written prose.

Why this exists: a hand-typed hint string ("dirb <url> [--wordlist <path>]") can drift from the tool's real
argparse the moment either one is edited without the other - that drift is exactly what `boxcutter irvin
--check` used to exist to catch after the fact. Deriving the schema directly FROM each tool's own
`add_arguments()` makes drift structurally impossible: the schema IS the argparse, introspected, so there is
nothing left to check separately.

Two kinds of information stay hand-authored, because argparse cannot express them: which flags are POLICY-
restricted for agents even though the underlying binary accepts them (``--opt-args`` on every tool that has it
except sqlmap - see `_OPT_ARGS_ALLOWED`), and short tradecraft notes about how to use a field well (see
`_NOTES`). Both are kept intentionally tiny; everything else is generated.

Imports of the tool registry are LAZY (done inside each function) to avoid an import cycle: tools.registry
-> ai.irvin -> irvin.pipeline -> irvin.agents -> irvin.agents.base -> here.
"""

from __future__ import annotations

import argparse
from functools import lru_cache

# CLI/output plumbing every tool inherits from add_common_args() - meaningless to an agent driving one call
# in-process (its result comes back as the return value, not a file) and, for --output/--table, actively
# harmful (it would divert the JSON envelope away from the stdout the runner captures).
_INTERNAL_DESTS = {"output", "jsonl", "debug", "table"}

# --opt-args forwards NATIVE flags of the wrapped binary verbatim - real in several tools' argparse, but
# deliberately exposed to agents on sqlmap ONLY (its one appropriate use: passing sqlmap-specific tuning).
# Excluding the property from every other tool's schema makes that policy structural, not a prompt request.
_OPT_ARGS_ALLOWED = {"sqlmap"}

# Flags real in a tool's argparse but POLICY-restricted for agents - the same idea as _OPT_ARGS_ALLOWED. An
# agent must NOT hand-pick fuzz payloads: fuzz's default mode already runs a comprehensive built-in payload
# DATABASE covering every class, and a hand-picked subset is strictly weaker. A specific one-off custom payload
# belongs in an http-request, not a fuzz --payload. Hiding these from the agent schema makes it structural,
# not a prompt request the model can ignore (which it did).
_AGENT_HIDDEN = {"fuzz": {"payload", "payload_file"}}

# Hand-authored tradecraft that is about HOW to use a field well, not WHICH fields exist - kept deliberately
# small. Anything expressible as "this flag exists / takes a value / has these choices" is generated below,
# so it can never drift from what the tool actually accepts.
_NOTES = {
    "fuzz": "Put {FUZZ} in ONE field of a realistic body/URL - never send bare '{FUZZ}' as the whole body. You "
            "have NO payload option here on purpose: fuzz carries a comprehensive built-in payload DATABASE that "
            "already covers every class (sqli/xss/ssti/lfi/xxe/nosql/rce/error-disclosure), each baseline-diffed "
            "against the unfuzzed response and reliability-reconfirmed by re-firing - always stronger and "
            "broader than a hand-picked list. Just point {FUZZ} at the input and run it. To try ONE specific "
            "custom payload at an exact injection point, send it with http-request instead.",
    "sqlmap": "Reproduce the exact injectable request (method/body/cookie/auth) first; justify heavier "
              "--level/--risk in opt_args only when a clean run fails.",
    "nuclei": "Target a category via tags (exposure,misconfig,cve,...) rather than an untagged full scan.",
    "swagger-endpoints": "Set fuzzable=true to get {FUZZ}-marked variants ready for the fuzz tool.",
    "dirb": "The only wordlists in this image are dirb's own bundled set (default: "
            "/usr/share/dirb/wordlists/common.txt). There is NO seclists or other path - do not invent one "
            "(e.g. /usr/share/seclists/...). OMIT wordlist to use the default; a path that doesn't exist is "
            "ignored and the default is used anyway.",
    "visual-driver": "You act by COORDINATES read off the grid on the returned screenshot (x,y in viewport "
                     "pixels; labeled every 100px). Every coordinate you pass came from the LAST screenshot, "
                     "so only chain actions that stay on the SAME screen - after a click that navigates or "
                     "reflows, stop and read the new screenshot before aiming again. Type __USER_x__/__PASS_x__ "
                     "tokens for credentials (substituted privately); never type a real password.",

    # -- HOW-TO-INVOKE tradecraft for the rest of the registry. The single most common failure is passing the
    # WRONG SHAPE in the positional (a bare host where a full param-bearing URL is needed, a URL where a bare
    # domain is needed, or the thing-to-explore left OUT of the URL). Each note below states that shape.
    "path-bust": "The directory to explore goes INSIDE the target URL - there is NO separate path flag. To bust "
                 "under /admin pass target='https://host/admin', NOT 'https://host'. Add --depth N to recurse "
                 "into found dirs, --extensions php,bak,old to append extensions, --codes 200,301,403 to widen "
                 "what counts as found, --full for the big ~12k wordlist. Omit --wordlist for the curated list.",
    "path-fuzz": "You place the marker yourself: the target must be a URL TEMPLATE containing FUZZ where each "
                 "word is substituted, e.g. 'https://host/api/FUZZ' or 'https://host/FUZZ.php'. This is how you "
                 "fuzz a mid-path or filename segment (path-bust only appends at the end). Omit --wordlist for "
                 "the built-in list; --full for the big one.",
    "smart-enum": "There is NO target URL - it DERIVES new candidate paths from ones you've already OBSERVED. "
                  "Pass real observed URLs/paths via --urls (comma-list or a file). It pivots versions "
                  "(/v1->/v2), walks numeric ids, flips singular/plural, and adds high-value siblings, then "
                  "emits a list you feed to path-fuzz / http-request. Seed it with real hits, not guesses.",
    "api-map": "Point the positional at the API base ('https://host' or 'https://host/api'); it probes a "
               "built-in API-route wordlist there and reports live endpoints + methods. Seed it with routes you "
               "already saw via --paths (comma-list or a file). Follow up on hits with http-request.",
    "http-request": "Your scalpel for ONE exact request - use it to CONFIRM a hypothesis, replay an edited "
                    "captured request, or fetch a JS bundle as source. Positional is the full URL; --data adds a "
                    "body (implies POST unless --method set); --method for PUT/PATCH/DELETE/OPTIONS; --header is "
                    "repeatable ('Name: value'). A body write mutates - only in authorised scope.",
    "js-endpoints": "Extracts URLs/paths/endpoints from ONE JavaScript file - the positional is the FULL .js URL "
                    "(not the page). Set --base-url to resolve relative paths; pass an auth --header for bundles "
                    "behind a login. An SPA's hidden/undocumented API routes hide here - run it on every app-own "
                    "bundle you find.",
    "katana-crawl": "Fast link/endpoint crawler of the positional URL. --js for script URLs only, --params for "
                    "param-bearing URLs only; pass an auth --header to crawl authenticated. Quick surface map; "
                    "use harvest for a deeper JS-app crawl and zap-crawl when you need ZAP's AJAX spider.",
    "harvest": "The deepest authenticated recon pass: positional is the start URL; it clicks/fills to reach app "
               "states and captures every request. Reuse a logged-in browser --session to crawl BEHIND auth; "
               "bound it with --max-pages / --max-time. Best single map of a JS app's real request surface.",
    "dirsearch": "Directory/file brute-force against the positional URL - include the subpath you want "
                 "enumerated (e.g. 'https://host/admin') to bust under it. Pass an auth --header to reach "
                 "content behind a login.",
    "screenshot": "Render the positional URL in headless chromium to a PNG (+ optional --source for the rendered "
                  "HTML). --full-page for the whole scrollable page, --wait ms for JS-heavy apps. Recon/triage "
                  "only - to PROVE an XSS actually fired use vision-verify, not this.",
    "vision-verify": "The definitive XSS proof: the positional is a URL carrying your payload and --marker is "
                     "the UNIQUE string your payload triggers (e.g. a window.__bcvvfire(1) canary). It loads the "
                     "page in chromium and reports EXECUTED vs merely-reflected. Always confirm a reflected/DOM "
                     "XSS candidate here before recording it as a finding - reflection alone is not execution.",
    "blind-oracle": "For BLIND (no visible output) sqli/injection. The positional URL must ALREADY carry the "
                    "params to test ('https://host/x?id=1&q=a'), or give a base URL + --data for a POST body. It "
                    "confirms via boolean/time-based differentials, so it needs a real param that reaches a "
                    "query; narrow with --param when you know the sink.",
    "bola-walk": "Two-identity IDOR/BOLA walk: positional is a URL with a CONCRETE object id "
                 "('https://host/api/orders/1042'). Put the owner's auth in --session-a and the attacker's in "
                 "--session-b (repeatable 'Name: value'), and the id set to walk in --range ('1000-1050' or "
                 "'1,2,3'). B getting A's object back is the finding.",
    "mass-assign": "Mass-assignment / privileged-field test: positional is the WRITE endpoint "
                   "('https://host/api/account'); -D is the baseline JSON body it expects; -X POST|PUT|PATCH. It "
                   "injects privileged fields (role/is_admin/...) and, with --verify <read endpoint>, CONFIRMS "
                   "the elevated state persisted. It MUTATES - authorised scope only.",
    "graphql-detect": "Find the GraphQL endpoint first: positional is a host or URL; it probes the common paths "
                      "(/graphql, /api/graphql, ...). Feed a confirmed endpoint into graphql-audit.",
    "graphql-audit": "Audit a KNOWN GraphQL endpoint - the positional is the FULL /graphql URL (run "
                     "graphql-detect first if you only have a host). Checks introspection, field suggestions, "
                     "batching and excessive-data exposure; pass an auth --header to audit the authed schema.",
    "swagger-specs": "Locate OpenAPI/Swagger spec URLs on a host (positional): probes the common spec paths "
                     "(/openapi.json, /swagger.json, /v2/api-docs, ...). Feed a found spec URL into "
                     "swagger-endpoints (for {FUZZ}-ready variants) or swagger-parser (for concrete URLs).",
    "swagger-parser": "Parse a KNOWN spec into concrete request URLs - the positional is the FULL spec URL; "
                      "--base-url resolves relative server paths. Use swagger-endpoints instead when you want "
                      "{FUZZ}-marked variants ready to fuzz.",
    "scan-secrets": "Scan the positional URL's response/asset for leaked keys/tokens/secrets. Pass an auth "
                    "--header to scan behind a login. Point it at JS bundles and config responses - that is "
                    "where secrets actually leak.",
    "git-extract": "Dump an exposed .git repo: positional is the site BASE url ('https://host'). It probes "
                   "/.git/ and reconstructs source when the repo is served. A hit is source/secret disclosure - "
                   "grep the recovered tree for creds and hidden endpoints.",
    "httpx": "Liveness/tech triage of the positional host or URL: status, title, server, tech fingerprint. A "
             "cheap first look before deeper testing.",
    "browser-actions": "Scripted headless browser: positional is the start URL; drive it with repeatable "
                       "--action steps run in order ('fill:#user=admin', 'click:text=Log in'). Attach to a "
                       "logged-in --session <id> to keep SPA state across calls.",
    "browser-login": "Log in through a REAL browser (use when a JS form login is required, not a raw API POST): "
                     "positional is the LOGIN PAGE url, --creds user:password. Returns the authenticated session "
                     "for reuse by other tools via --session.",
    "wayback": "Historical URLs for the positional BARE domain ('example.com', not a URL) from public archives. "
               "--params keeps only param-bearing URLs (best for finding old injectable endpoints), --js only "
               "scripts, --inc_subdomains widens. A cheap way to surface removed/forgotten endpoints to probe "
               "live.",
    "wayback-domains": "Like wayback but returns just the unique HOST list for the positional bare domain - "
                       "archive-based subdomain discovery.",
    "subfinder": "Passive subdomain discovery for the positional BARE domain (no scheme). Recon only; stay "
                 "within authorised scope.",
    "dns-brute": "Subdomain brute-force: positional is the BARE domain ('example.com', not a URL); uses the "
                 "bundled subdomains wordlist by default. Off-host recon - use only within authorised scope.",
    "dnsx": "Resolve or brute-force DNS: give a single name as the positional, OR --list a file of names, OR "
            "--domain + --wordlist to brute. Bare names, no scheme.",
    "zap-crawl": "Crawl the positional URL with ZAP's AJAX + traditional spider (needs the ZAP proxy up). "
                 "--js/--params filter the output. Heavier than katana - reach for it when a JS app needs the "
                 "AJAX spider to reveal its requests.",
    "zap-scan-url": "ZAP ACTIVE scan of ONE exact URL (no crawling; needs ZAP up). It sends real attack traffic, "
                    "so authorised in-scope targets only. Use on a single suspicious endpoint.",
    "zap-scan-full": "ZAP ACTIVE scan of the whole target - spider + AJAX spider + active attacks (needs ZAP "
                     "up). Heavy, slow and mutating: authorised in-scope only, and prefer targeted tools first; "
                     "reserve this for a broad sweep.",
    "zap-scan-openapi": "ZAP ACTIVE scan driven by an OpenAPI/Swagger spec - positional is the SPEC URL (needs "
                        "ZAP up). Strong coverage of a documented API's operations; sends attack traffic, so "
                        "authorised in-scope only.",
}

_TYPE = {int: "integer", float: "number"}


def _prop(action: argparse.Action) -> dict | None:
    """The JSON-schema property for one argparse action, or None if it isn't agent-facing (help/version)."""
    cls = type(action).__name__
    if cls in ("_HelpAction", "_VersionAction"):
        return None
    if cls in ("_StoreTrueAction", "_StoreFalseAction"):
        return {"type": "boolean"}
    if cls == "_AppendAction":
        return {"type": "array", "items": {"type": "string"}}
    prop = {"type": _TYPE.get(action.type, "string")}
    if action.choices:
        prop["enum"] = list(action.choices)
    return prop


@lru_cache(maxsize=None)
def build(name: str) -> dict:
    """One tool's native schema, derived from its real argparse: {name, description, schema (JSON Schema
    object), flag_of (dest -> flag string, or None for a positional - lets to_argv() translate a structured
    call back into the argv list boxcutter's own CLI already knows how to run)}."""
    from .registry import BY_NAME
    mod = BY_NAME[name]
    parser = argparse.ArgumentParser(prog=name, add_help=False)
    mod.add_arguments(parser)

    props, required, flag_of = {}, [], {}
    for a in parser._actions:
        if a.dest in _INTERNAL_DESTS:
            continue
        if a.dest == "opt_args" and name not in _OPT_ARGS_ALLOWED:
            continue
        if a.dest in _AGENT_HIDDEN.get(name, ()):        # policy-restricted for agents (see _AGENT_HIDDEN)
            continue
        prop = _prop(a)
        if prop is None:
            continue
        prop["description"] = a.help or ""
        props[a.dest] = prop
        if a.option_strings:
            flag_of[a.dest] = a.option_strings[-1]          # prefer the long form, e.g. --header over -H
        else:
            flag_of[a.dest] = None                            # positional
            if a.nargs not in ("?", "*"):
                required.append(a.dest)

    note = _NOTES.get(name)
    description = mod.HELP + (f" NOTE: {note}" if note else "")
    return {
        "name": name,
        "description": description,
        "schema": {"type": "object", "properties": props, "required": required, "additionalProperties": False},
        "flag_of": flag_of,
    }


def to_argv(name: str, args: dict) -> list[str]:
    """Translate one native tool call's structured args back into the argv list the dispatch layer (the
    shared Runner -> boxcutter's own CLI) already knows how to execute - no change needed there."""
    spec = build(name)
    props = spec["schema"]["properties"]
    args = args or {}
    positionals, flags = [], []
    for dest, flag in spec["flag_of"].items():
        if dest not in args:
            continue
        val = args[dest]
        # some models serialize an array-typed arg as a JSON STRING (e.g. action='["click:1,2","wait"]')
        # instead of a real list - coerce it back so a repeatable flag like --action still expands correctly.
        if props.get(dest, {}).get("type") == "array" and isinstance(val, str):
            s = val.strip()
            if s.startswith("[") and s.endswith("]"):
                try:
                    import json as _json
                    parsed = _json.loads(s)
                    if isinstance(parsed, list):
                        val = parsed
                except Exception:  # noqa: BLE001 - not valid JSON; leave as-is
                    pass
        if flag is None:
            if val not in (None, ""):
                positionals.append(str(val))
            continue
        if val is None or val is False or val == "":
            continue
        if val is True:
            flags.append(flag)
        elif isinstance(val, list):
            for v in val:
                flags += [flag, str(v)]
        else:
            flags += [flag, str(val)]
    return [name, *positionals, *flags]


def native_tools(names) -> list[dict]:
    """{name, description, schema} for each tool - the shape provider.send() hands to the LLM API."""
    return [{k: v for k, v in build(n).items() if k != "flag_of"} for n in names]


def validate(names) -> list[str]:
    """Return problem strings for any tool name that isn't a real, buildable boxcutter sub-command - the
    check that used to require a separate manual `--check` invocation, now cheap enough to run automatically
    at registry-build time (see agents/__init__.py) so a typo'd tool name fails on process start, not in a
    live run."""
    from .registry import BY_NAME
    problems = []
    for n in names:
        if n not in BY_NAME:
            problems.append(f"'{n}' is not a boxcutter sub-command")
            continue
        try:
            build(n)
        except Exception as exc:  # noqa: BLE001 - any introspection failure is itself the problem to report
            problems.append(f"'{n}' failed to build a schema: {exc}")
    return problems

"""Accepted CLI flags per boxcutter tool — the source of truth for argument validation in the UI.

Each boxcutter tool wrapper accepts a SMALL fixed set of flags (its own, plus the shared ``--output/--json/
--debug/--table/...``); tool-native scanner flags must go through ``--opt-args`` instead. Passing an unaccepted
flag (e.g. ``-severity critical,high`` to ``nuclei``) makes the engine abort with "unrecognized arguments", and
that only shows up mid-scan. The builder / New Scan use this map to flag a bad argument BEFORE the scan runs.

Generated from the engine's own argparse parsers (``boxcutter.tools.*.add_arguments``) — regenerate with
``python scripts/gen_tool_flags.py`` whenever a tool's flags change; the engine remains the source of truth."""
from __future__ import annotations

# tool -> sorted list of every accepted flag (long and short). A tool absent from the map isn't validated.
TOOL_FLAGS: dict[str, list[str]] = {
    "api-map": ["--budget", "--concurrency", "--debug", "--header", "--json", "--jsonl", "--max-paths",
                "--methods", "--output", "--paths", "--table", "-H"],
    "blind-oracle": ["--data", "--debug", "--delay", "--header", "--json", "--jsonl", "--len-delta",
                     "--output", "--param", "--table", "-H"],
    "bola-walk": ["--concurrency", "--debug", "--json", "--jsonl", "--output", "--range", "--session-a",
                  "--session-b", "--table", "-A", "-B"],
    "browser-actions": ["--action", "--actions-file", "--debug", "--header", "--json", "--jsonl", "--output",
                        "--session", "--table", "--timeout", "-H"],
    "browser-login": ["--creds", "--debug", "--json", "--jsonl", "--output", "--table", "--timeout"],
    "dirb": ["--debug", "--json", "--jsonl", "--opt-args", "--output", "--table", "--timeout", "--wordlist"],
    "dirsearch": ["--debug", "--header", "--json", "--jsonl", "--output", "--table", "--timeout", "-H"],
    "dns-brute": ["--debug", "--json", "--jsonl", "--output", "--rate", "--resp", "--table", "--timeout",
                  "--wildcard", "--wordlist"],
    "dnsx": ["--debug", "--domain", "--json", "--jsonl", "--list", "--output", "--rate", "--resp", "--table",
             "--timeout", "--wildcard", "--wordlist"],
    "extract-domains": ["--debug", "--header", "--json", "--jsonl", "--output", "--table", "--timeout", "-H"],
    "fuzz": ["--data", "--debug", "--header", "--json", "--jsonl", "--method", "--output", "--pattern",
             "--payload", "--payload-file", "--status", "--table", "--timeout", "-H"],
    "git-extract": ["--debug", "--json", "--jsonl", "--output", "--table"],
    "graphql-audit": ["--debug", "--header", "--json", "--jsonl", "--output", "--table", "--timeout", "-H"],
    "graphql-detect": ["--debug", "--header", "--json", "--jsonl", "--output", "--table", "--timeout", "-H"],
    "harvest": ["--capture-host", "--debug", "--har", "--header", "--include-assets", "--json", "--jsonl",
                "--max-actions", "--max-pages", "--max-time", "--output", "--scope", "--session", "--table",
                "--timeout", "-H"],
    "http-request": ["--data", "--debug", "--header", "--json", "--jsonl", "--method", "--output", "--table",
                     "-D", "-H", "-X"],
    "httpx": ["--debug", "--header", "--json", "--jsonl", "--opt-args", "--output", "--table", "--timeout", "-H"],
    "js-endpoints": ["--base-url", "--debug", "--header", "--json", "--jsonl", "--output", "--table", "-H"],
    "js-files": ["--debug", "--header", "--json", "--jsonl", "--max-files", "--no-verify", "--output", "--table",
                 "--timeout", "-H"],
    "katana-crawl": ["--debug", "--header", "--js", "--json", "--jsonl", "--opt-args", "--output", "--params",
                     "--table", "--timeout", "-H"],
    "liveless": ["--concurrency", "--debug", "--endpoint", "--json", "--jsonl", "--list", "--output", "--table",
                 "--timeout"],
    "mass-assign": ["--data", "--debug", "--header", "--json", "--jsonl", "--method", "--output", "--table",
                    "--verify", "-D", "-H", "-X"],
    "nmap": ["--debug", "--json", "--jsonl", "--output", "--ports", "--table", "--timeout", "--top-ports"],
    "nuclei": ["--debug", "--header", "--json", "--jsonl", "--opt-args", "--output", "--table", "--tags", "-H"],
    "nuclei-dast": ["--debug", "--header", "--json", "--jsonl", "--opt-args", "--output", "--table", "--tags", "-H"],
    "path-bust": ["--codes", "--debug", "--depth", "--extensions", "--full", "--header", "--json", "--jsonl",
                  "--method", "--output", "--table", "--timeout", "--wordlist", "-H"],
    "path-fuzz": ["--codes", "--debug", "--extensions", "--full", "--header", "--json", "--jsonl", "--method",
                  "--output", "--table", "--timeout", "--wordlist", "-H"],
    "ping-scan": ["--debug", "--json", "--jsonl", "--output", "--table", "--timeout"],
    "scan-secrets": ["--debug", "--header", "--json", "--jsonl", "--no-verify", "--output", "--table",
                     "--verify", "-H"],
    "screenshot": ["--debug", "--full-page", "--header", "--json", "--jsonl", "--output", "--save", "--save-thumb",
                   "--source", "--table", "--thumb-scale", "--timeout", "--wait", "-H", "-d", "-s"],
    "smart-enum": ["--debug", "--json", "--jsonl", "--max", "--output", "--table", "--urls", "--wordlist"],
    "sqlmap": ["--data", "--debug", "--header", "--json", "--jsonl", "--method", "--opt-args", "--output",
               "--table", "--timeout", "-H"],
    "subfinder": ["--debug", "--json", "--jsonl", "--output", "--table"],
    "swagger-endpoints": ["--debug", "--fuzzable", "--header", "--json", "--jsonl", "--output", "--table", "-H"],
    "swagger-parser": ["--base-url", "--debug", "--header", "--json", "--jsonl", "--output", "--table", "-H"],
    "swagger-specs": ["--debug", "--header", "--json", "--jsonl", "--output", "--table", "-H"],
    "vision-verify": ["--debug", "--header", "--json", "--jsonl", "--marker", "--output", "--save", "--table",
                      "--wait", "-H"],
    "visual-driver": ["--action", "--debug", "--dump-storage", "--grid", "--header", "--json", "--jsonl",
                      "--output", "--session", "--table", "--timeout", "--trace", "--trace-each", "-H"],
    "wayback": ["--all", "--cc-indexes", "--debug", "--inc-subdomains", "--inc_subdomains", "--js", "--json",
                "--jsonl", "--output", "--params", "--table", "--timeout"],
    "wayback-domains": ["--debug", "--json", "--jsonl", "--output", "--table", "--timeout"],
    "zap-crawl": ["--debug", "--header", "--js", "--json", "--jsonl", "--output", "--params", "--table",
                  "--timeout", "-H"],
    "zap-scan-full": ["--debug", "--header", "--json", "--jsonl", "--output", "--table", "--timeout", "-H"],
    "zap-scan-openapi": ["--debug", "--header", "--json", "--jsonl", "--output", "--table", "--timeout", "-H"],
    "zap-scan-url": ["--debug", "--header", "--json", "--jsonl", "--output", "--table", "--timeout", "-H"],
}


def _is_flag(tok: str) -> bool:
    """A token is a flag if it starts with '-' and isn't a negative number (so '-5' is a value, '-H' a flag)."""
    return tok.startswith("-") and not (len(tok) > 1 and (tok[1].isdigit() or tok[1] == "."))


def unknown_flags(tool: str, tokens) -> list[str]:
    """Flags in ``tokens`` that ``tool`` does not accept (so they'd be rejected at run time). Returns [] for a
    tool we don't have a flag list for (don't guess). The value right after ``--opt-args`` is verbatim passthrough
    to the underlying binary, so flags inside it are NOT validated."""
    allowed = TOOL_FLAGS.get(tool)
    if not allowed:
        return []
    bad: list[str] = []
    skip_next = False
    for tok in tokens:
        if skip_next:                       # the value following --opt-args is forwarded verbatim
            skip_next = False
            continue
        if not _is_flag(tok):
            continue
        flag = tok.split("=", 1)[0]
        if flag not in allowed:
            bad.append(flag)
        elif flag == "--opt-args":
            skip_next = True
    # keep first-seen order, de-duped
    seen: set = set()
    return [f for f in bad if not (f in seen or seen.add(f))]

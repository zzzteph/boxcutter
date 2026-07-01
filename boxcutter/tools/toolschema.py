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
-> tools.irvin -> irvin.pipeline -> irvin.agents -> irvin.agents.base -> here.
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

# Hand-authored tradecraft that is about HOW to use a field well, not WHICH fields exist - kept deliberately
# small. Anything expressible as "this flag exists / takes a value / has these choices" is generated below,
# so it can never drift from what the tool actually accepts.
_NOTES = {
    "fuzz": "Put {FUZZ} in ONE field of a realistic body/URL - never send bare '{FUZZ}' as the whole body. "
            "OMIT payload/payload_file for breadth: the default mode already runs the full built-in battery "
            "(sqli/xss/ssti/lfi/xxe/nosql/rce/error-disclosure), each baseline-diffed against the unfuzzed "
            "response and reliability-reconfirmed by re-firing - stronger and broader than a hand-picked list. "
            "Only set payload/payload_file for a specific technique or context (e.g. an XSS breakout shaped "
            "for one exact injection point) the built-in battery doesn't cover; don't reinvent a weaker subset "
            "of what the default mode already tests.",
    "sqlmap": "Reproduce the exact injectable request (method/body/cookie/auth) first; justify heavier "
              "--level/--risk in opt_args only when a clean run fails.",
    "nuclei": "Target a category via tags (exposure,misconfig,cve,...) rather than an untagged full scan.",
    "swagger-endpoints": "Set fuzzable=true to get {FUZZ}-marked variants ready for the fuzz tool.",
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
    args = args or {}
    positionals, flags = [], []
    for dest, flag in spec["flag_of"].items():
        if dest not in args:
            continue
        val = args[dest]
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

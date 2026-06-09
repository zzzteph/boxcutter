"""Helpers shared by workflows.

A workflow takes a single positional target by default. Per-tool arguments can
be added with the repeatable ``--arg`` option, e.g.::

    boxcutter workflow full-scan example.com --arg fuzz="--timeout 60" \
        --arg nuclei="--opt-args '-tags cve'"

``call(module, base_argv, args)`` runs a tool with the workflow's base argv plus
any user override for that tool (appended, so the user's value wins).
"""

from __future__ import annotations

import shlex
from types import SimpleNamespace

from ..core import fsutil
from ..core.envelope import read_envelope
from ..core.runner import tool_data

# Tools that accept a "--header" option; a workflow's --header propagates to
# these. ZAP tools inject the headers into every request via the Replacer
# add-on; swagger discovery/parse tools use them to fetch the spec.
HEADER_CAPABLE = {
    "nuclei", "httpx", "tech-detect", "katana-crawl", "sqlmap", "dirsearch",
    "screenshot", "fuzz", "path-fuzz", "http-request", "swagger-parser",
    "swagger-specs", "swagger-endpoints",
    "zap-scan-url", "zap-scan-openapi", "zap-scan-full", "zap-crawl",
}


def add_steps_option(parser) -> None:
    """Add the ``--steps`` flag (print each step to stderr; otherwise silent)."""
    parser.add_argument(
        "--steps",
        action="store_true",
        help="Print each step to stderr as it runs (default: silent)",
    )


def add_overrides_option(parser) -> None:
    """Add the repeatable ``--arg TOOL=ARGS`` override option."""
    parser.add_argument(
        "--arg",
        dest="tool_overrides",
        action="append",
        default=[],
        metavar='TOOL="ARGS"',
        help='Extra arguments for one underlying tool, e.g. --arg fuzz="--timeout 60". Repeatable.',
    )


def add_header_option(parser) -> None:
    """Add the repeatable ``--header`` option, propagated to header-capable tools."""
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="Request header passed to every tool that supports it, e.g. "
             "'Authorization: Bearer ...' (repeatable)",
    )


def _parse_overrides(items: list[str] | None) -> dict[str, list[str]]:
    overrides: dict[str, list[str]] = {}
    for raw in items or []:
        if "=" not in raw:
            continue
        name, value = raw.split("=", 1)
        name = name.strip()
        if name:
            overrides[name] = shlex.split(value)
    return overrides


def call(module, base_argv: list[str], args) -> list:
    """Run ``module`` with ``base_argv`` plus the user's ``--arg`` override, and
    propagate any workflow ``--header`` to tools that support one."""
    overrides = _parse_overrides(getattr(args, "tool_overrides", None))
    argv = [*base_argv, *overrides.get(module.NAME, [])]
    if module.NAME in HEADER_CAPABLE:
        for header in getattr(args, "header", []) or []:
            argv += ["--header", header]
    return tool_data(module, argv)


def run_workflow(module, target: str, args) -> list:
    """Run another workflow ``module`` on ``target`` and return its data list.

    Lets a meta-workflow (e.g. env-scan) drive other workflows. Propagates
    ``--debug`` and any ``--arg`` overrides; the sub-workflow's envelope goes to
    a temp file which is read back and removed.
    """
    out = fsutil.temp_file("metawf_")
    module.run(
        SimpleNamespace(
            target=target,
            debug=getattr(args, "debug", False),
            steps=getattr(args, "steps", False),
            output=out,
            tool_overrides=getattr(args, "tool_overrides", []),
            header=getattr(args, "header", []),
        )
    )
    data = read_envelope(out).get("data", []) or []
    fsutil.remove(out)
    return data


def finding(source: str, f: dict, url: str | None = None) -> dict:
    """Tag a tool finding with its source, in the standard finding shape.

    ``source`` records which tool produced it. The finding's own ``url`` wins;
    ``url`` is the fallback (the target the workflow ran the tool on).
    """
    return {
        "source": source,
        "severity": f.get("severity", "info"),
        "title": f.get("title", ""),
        "info": f.get("info", ""),
        "url": f.get("url") or url or "",
    }

"""boxcutter CLI - a single dispatcher over every tool subcommand.

Usage::

    boxcutter <tool> <target> [options]
    boxcutter nuclei https://example.com --output findings.json
    boxcutter subfinder example.com
    boxcutter --list

Every tool emits a JSON envelope ``{success, data, error}`` on stdout (or to
``--output``). Diagnostics go to stderr, so stdout is always parseable JSON.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

from . import __version__
from .core import capability
from .core.args import add_common_args, add_severity_arg
from .core.envelope import output_result, set_output_kind, set_severity_filter, set_table_mode
from .workflows import WORKFLOWS
from .workflows._common import add_header_option, add_overrides_option, add_steps_option
from .tools.registry import TOOLS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="boxcutter",
        description="Containerised pentesting toolkit - JSON-emitting wrappers around "
        "scanning tools. Each subcommand returns {success, data, error}.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"boxcutter {__version__}")
    parser.add_argument("--list", action="store_true", help="List tools usable in this image and exit")
    parser.add_argument("--list-all", dest="list_all", action="store_true",
                        help="List every tool, including ones not installed in this image")

    subparsers = parser.add_subparsers(dest="tool", metavar="<tool>")
    for module in TOOLS:
        sub = subparsers.add_parser(module.NAME, help=module.HELP, description=module.HELP)
        module.add_arguments(sub)
        # --severity is a findings filter, so only expose it on tools that emit
        # findings; for url/items tools it would do nothing.
        if getattr(module, "KIND", "items") == "findings":
            add_severity_arg(sub)
        sub.set_defaults(_run=module.run, _tool_name=module.NAME,
                         _kind=getattr(module, "KIND", "items"))

    _add_raw_parser(subparsers)
    _add_workflow_parser(subparsers)
    return parser


def _add_workflow_parser(subparsers: argparse._SubParsersAction) -> None:
    wf = subparsers.add_parser(
        "workflow",
        help="Run a multi-tool workflow (chains tools, presents one result).",
        description="Run a workflow: a recipe that chains several tools and emits a "
        "combined result. Use `boxcutter workflow --list` to see them.",
    )
    # distinct dest so it doesn't collide with the top-level --list in main()
    wf.add_argument("--list", dest="workflow_list", action="store_true",
                    help="List workflows and exit")
    wf_sub = wf.add_subparsers(dest="workflow", metavar="<name>")
    for module in WORKFLOWS:
        sub = wf_sub.add_parser(module.NAME, help=module.HELP, description=module.HELP)
        module.add_arguments(sub)
        add_common_args(sub)
        add_severity_arg(sub)
        add_overrides_option(sub)
        add_steps_option(sub)
        add_header_option(sub)
        sub.set_defaults(_run=module.run)
    wf.set_defaults(_run=_run_workflow_index)


def _run_workflow_index(args) -> int:
    width = max(len(m.NAME) for m in WORKFLOWS)
    print("Available workflows:\n")
    for module in WORKFLOWS:
        print(f"  {module.NAME.ljust(width)}  {module.HELP}")
    print("\nRun one with:  boxcutter workflow <name> <target>")
    return 0


# Bundled tools that aren't a bare binary on PATH get an explicit launcher.
RAW_ALIASES: dict[str, list[str]] = {
    "sqlmap": ["python3", "/usr/share/sqlmap/sqlmap.py"],
    "dirsearch": ["python3", "/usr/share/dirsearch/dirsearch.py"],
    "zap": ["/usr/share/zaproxy/zap.sh"],
    "zap.sh": ["/usr/share/zaproxy/zap.sh"],
}


def _add_raw_parser(subparsers: argparse._SubParsersAction) -> None:
    raw = subparsers.add_parser(
        "raw",
        aliases=["run"],
        help="Run a bundled scanner directly, passing args through as-is (no JSON wrapper).",
        description="Run a bundled scanner binary directly with its native flags and output. "
        "Example: boxcutter raw nuclei -u https://example.com -t cves",
    )
    raw.add_argument("tool_name", metavar="<binary>",
                     help="Tool to run: any binary on PATH, or sqlmap/dirsearch/zap")
    raw.add_argument("tool_args", nargs=argparse.REMAINDER,
                     help="Arguments forwarded verbatim to the tool")
    raw.set_defaults(_run=_run_raw)


def _run_raw(args) -> int:
    """Exec a bundled tool with inherited stdio - no envelope, native output."""
    launcher = RAW_ALIASES.get(args.tool_name, [args.tool_name])
    cmd = [*launcher, *args.tool_args]
    try:
        return subprocess.run(cmd).returncode
    except FileNotFoundError:
        sys.stderr.write(f"boxcutter: '{args.tool_name}' not found on PATH\n")
        return 127


def _print_tool_list(show_all: bool = False) -> None:
    width = max(len(m.NAME) for m in TOOLS)
    print("Available tools:\n")
    hidden = []
    for module in TOOLS:
        ok = capability.name_available(module.NAME)
        if not ok and not show_all:
            hidden.append(module)
            continue
        mark = "" if ok else f"   [needs {capability.requirement_for(module.NAME)}]"
        print(f"  {module.NAME.ljust(width)}  {module.HELP}{mark}")
    if hidden:
        reqs = ", ".join(sorted({capability.requirement_for(m.NAME) for m in hidden}))
        print(f"\n  {len(hidden)} more not installed here ({reqs}) - run 'boxcutter --list-all' to show")
    print("\nMulti-tool workflows:  boxcutter workflow --list")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "list_all", False):
        _print_tool_list(show_all=True)
        return 0

    if getattr(args, "list", False):
        _print_tool_list()
        return 0

    if not getattr(args, "tool", None):
        parser.print_help()
        return 1

    set_table_mode(getattr(args, "table", False))
    set_output_kind(getattr(args, "_kind", "items"))
    # Findings-only filter; a no-op for url/items output. Set once here so it
    # applies to a single tool and to a workflow's final aggregated output alike.
    set_severity_filter(getattr(args, "severity", None))

    # A tool whose external binary is missing in this image fails honestly.
    tname = getattr(args, "_tool_name", None)
    if tname and not capability.name_available(tname):
        output_result(
            [], getattr(args, "output", None),
            f"{tname} requires '{capability.requirement_for(tname)}' which is not installed in this image",
        )
        return 1

    try:
        return args._run(args)
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())

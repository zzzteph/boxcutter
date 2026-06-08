"""Common argparse wiring reused across tool subcommands."""

from __future__ import annotations

import argparse


def add_common_args(parser: argparse.ArgumentParser) -> None:
    """Add the ``--output`` / ``--debug`` options every tool shares."""
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="File path to save output as JSON envelope (default: stdout)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print progress/diagnostics to stderr",
    )
    parser.add_argument(
        "--table",
        action="store_true",
        help="Render results as a text table on stdout instead of JSON",
    )


def add_opt_args(parser: argparse.ArgumentParser) -> None:
    """Add the passthrough ``--opt-args`` option (extra flags for the binary)."""
    parser.add_argument(
        "--opt-args",
        dest="opt_args",
        default="",
        metavar="ARGS",
        help="Optional extra arguments forwarded verbatim to the underlying tool",
    )


def add_header_arg(parser: argparse.ArgumentParser) -> None:
    """Add the repeatable ``--header "Name: Value"`` request-header option."""
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="Extra request header, e.g. 'Authorization: Bearer ...' (repeatable)",
    )

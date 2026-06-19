"""Run a tool in-process and get its result back.

Workflows use this to chain tools together. ``run_tool`` builds the tool's own
argument parser (so defaults and validation match the CLI exactly), runs it into
a temp file, and returns the parsed envelope. The temp file is always JSON, so
``--table`` on the outer command never interferes.
"""

from __future__ import annotations

import argparse

from . import capability, fsutil
from .envelope import read_envelope, set_force_json_file


def run_tool(module, argv: list[str]) -> dict:
    """Run ``module`` (a tool) with CLI-style ``argv`` tokens; return its envelope.

    Example: ``run_tool(subfinder, ["example.com"])`` ->
    ``{"success": True, "data": [...], "error": None}``.
    """
    # In a slim image the tool's binary may be absent; skip it cleanly so the
    # workflow keeps going (the step just contributes no findings).
    if not capability.name_available(module.NAME):
        req = capability.requirement_for(module.NAME)
        return {"success": False, "data": [], "error": f"{module.NAME} requires '{req}' (not installed)"}

    parser = argparse.ArgumentParser(prog=module.NAME, add_help=False)
    module.add_arguments(parser)
    out = fsutil.temp_file("workflow_")
    try:
        # A bad sub-invocation (argparse SystemExit) or an unexpected error must
        # not abort the whole workflow; turn either into a failure envelope.
        try:
            args = parser.parse_args([*argv, "--output", out])
        except SystemExit:
            return {"success": False, "data": [], "error": f"{module.NAME}: invalid arguments {argv}"}
        # Force a JSON envelope into the temp file regardless of the user's
        # --output/--jsonl (which render tables / JSON-lines); the engine reads it
        # back as JSON to hand data to the next step.
        prev = set_force_json_file(True)
        try:
            module.run(args)
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "data": [], "error": f"{module.NAME}: {exc}"}
        finally:
            set_force_json_file(prev)
        return read_envelope(out)
    finally:
        fsutil.remove(out)


def tool_data(module, argv: list[str]) -> list:
    """Same as :func:`run_tool` but returns just the ``data`` list."""
    data = run_tool(module, argv).get("data", [])
    return data if isinstance(data, list) else []

"""Self-check: prove every executor can actually drive its tools, so a live run never hits 'unrecognized
arguments'. For each tool an executor declares it verifies the tool is a real boxcutter sub-command, is
allowed by the shared runner, has a usage hint, and that every flag the hint documents truly exists in the
tool's argparse. Run with `boxcutter irvin --check`.

Imports of the tool registry / runner are LAZY (done inside the function) to avoid an import cycle:
tools.registry -> tools.irvin -> irvin.pipeline -> irvin.agents.
"""

from __future__ import annotations

import argparse
import re

from .agents import EXECUTORS
from .agents.base import _TOOL_HINTS


def _documented_flags(hint: str) -> set:
    """Boxcutter-level flags a hint tells the agent to use - excluding --opt-args native payloads, quoted
    examples, <placeholders>, {markers}, and forbidden-flag prohibitions ('NO -X/--method')."""
    h = re.sub(r'"[^"]*"', "", hint)
    h = re.sub(r"<[^>]*>", "", h)
    h = re.sub(r"\bNO\b[^.;]*", "", h, flags=re.I)
    h = h.replace("{FUZZ}", "").replace("{NUMBERS}", "")
    return set(re.findall(r"(?<![\w-])(--?[A-Za-z][\w-]*)", h))


def check() -> list:
    """Return a list of problem strings (empty == everything validated)."""
    from ..orca.runner import ALLOWED          # lazy: avoid import cycle
    from ..tools.registry import BY_NAME

    problems = []
    for ex in EXECUTORS.values():
        for t in sorted(ex.tools):
            if t not in BY_NAME:
                problems.append(f"[{ex.name}] tool '{t}' is not a boxcutter sub-command")
                continue
            if t not in ALLOWED:
                problems.append(f"[{ex.name}] tool '{t}' is not in the runner ALLOWED set")
            if t not in _TOOL_HINTS:
                problems.append(f"[{ex.name}] tool '{t}' has no usage hint (agent flies blind)")
                continue
            parser = argparse.ArgumentParser(prog=t)
            BY_NAME[t].add_arguments(parser)
            real = {opt for a in parser._actions for opt in a.option_strings}
            for f in _documented_flags(_TOOL_HINTS[t]):
                if f not in ("-h", "--help") and f not in real:
                    problems.append(f"[{ex.name}] hint for '{t}' documents '{f}' which the tool does not accept "
                                    f"(real: {', '.join(sorted(real)) or 'none'})")
    return problems


def report() -> int:
    """Print the result; return a process exit code (0 ok, 1 problems)."""
    problems = check()
    tools = sorted({t for ex in EXECUTORS.values() for t in ex.tools})
    print(f"irvin self-check: {len(EXECUTORS)} executors, {len(tools)} distinct tools")
    print("tools: " + ", ".join(tools))
    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print("  - " + p)
        return 1
    print("\nOK - every tool is a real sub-command, allowed, hinted, and every documented flag is real.")
    return 0

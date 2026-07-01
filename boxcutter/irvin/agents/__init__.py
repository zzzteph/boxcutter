"""irvin agent registry - the ONLY place you wire agents into the pipeline.

To add a suggester: append an instance to SUGGESTERS. To add an executor: add it to EXECUTORS. The spine
in pipeline.py reads these registries and never needs to change.
"""

from __future__ import annotations

from .control import Adjuster, Concluder, Planner, Reporter, Reviewer, Thinner
from .executors import (AccessControl, Auth, Dirbust, Explorer, Exposure, GitDumper, PathTraversal, Recon,
                        Secrets, Spa, Sqli, WebVulnTriage, Xss)
from .suggesters import (AccessProfile, AuthProfile, DynamicSuggester, ExplorationProfile, ExposureProfile,
                         InjectionProfile, MinorityReport, ReconProfile)

# the MANAGERS (agent type 1) - each commissions verified work from the specialists in its lane, or stands
# down. The board, plus the mandated dissent (MinorityReport) which always commissions a divergent angle after
# seeing the board.
SUGGESTERS = [
    ReconProfile(),
    ExplorationProfile(),
    AccessProfile(),
    InjectionProfile(),
    ExposureProfile(),
    AuthProfile(),
    MinorityReport(),     # the dissent - always last, always speaks
]

# working agents (agent type 2) - one PROFESSIONAL specialist per security issue; each answers a manager's
# commission with verified results. name -> class
EXECUTORS = {e.name: e for e in (Recon, Spa, Explorer, Dirbust, AccessControl, WebVulnTriage, Sqli, Xss,
                                 PathTraversal, GitDumper, Secrets, Exposure, Auth)}

# detect -> exploit escalation: when an executor (e.g. web-vuln-triage) confirms a finding of one of these
# CLASSES, the pipeline spawns the matching exploitation specialist on that target IN THE SAME ROUND, so a
# triaged class doesn't wait a full round to be exploited. Only mappings whose target executor exists are kept.
ESCALATE = {cls: ex for cls, ex in
            {"sqli": "sqli", "xss": "xss", "lfi": "path-traversal", "traversal": "path-traversal"}.items()
            if ex in EXECUTORS}

# the control roles (one each). REVIEWER is a separate oversight org - it monitors the decision and can
# grow the council, but never overrides the head or the plan. THINNER runs between the planner and the
# executors to drop actions already done. ADJUSTER runs after each executor to prune/fix the remaining steps.
CONCLUDER = Concluder()
REVIEWER = Reviewer()
PLANNER = Planner()
THINNER = Thinner()
ADJUSTER = Adjuster()
REPORTER = Reporter()


def validate_registry() -> None:
    """Raise if any executor declares a tool that doesn't exist, can't build a native schema, or isn't in the
    shared runner's allowlist. This is the check `boxcutter irvin --check` used to require a human to remember
    to run by hand; every tool's agent-facing schema is now GENERATED from its real argparse (see
    tools/toolschema.py), so the one thing left that can actually go wrong - a typo'd tool name - is cheap
    enough to catch automatically. Called from tools/irvin.py's run(), not at import time here: this module
    loads partway through boxcutter.tools.registry building itself (registry -> tools.irvin -> irvin.pipeline
    -> here), so BY_NAME isn't fully populated yet at import time - only once the CLI actually runs is the
    whole package tree guaranteed to have finished loading."""
    from ..runner import ALLOWED
    from ...tools import toolschema
    problems = []
    for ex in EXECUTORS.values():
        problems += [f"[{ex.name}] {p}" for p in toolschema.validate(ex.tools)]
        problems += [f"[{ex.name}] tool '{t}' is not in the runner's ALLOWED set"
                     for t in ex.tools if t not in ALLOWED]
    if problems:
        raise RuntimeError("irvin executor registry is inconsistent:\n" + "\n".join("  - " + p for p in problems))


def executor_manual() -> str:
    """The planner's manual: exactly what each executor does, its tools, and its typical COST (low/med/high
    requests-and-time per commission) - so steps can be tailored and weighed against what a lane is yielding."""
    return "\n".join(f"  - {e.name}: {e.description}\n      tools: {', '.join(sorted(e.tools))}  cost: {e.cost}"
                     for e in EXECUTORS.values())

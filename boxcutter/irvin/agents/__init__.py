"""irvin agent registry - the ONLY place you wire agents into the pipeline.

To add a suggester: append an instance to SUGGESTERS. To add an executor: add it to EXECUTORS. The spine
in pipeline.py reads these registries and never needs to change.
"""

from __future__ import annotations

from .control import Adjuster, Concluder, Planner, Reporter, Reviewer
from .executors import (AccessControl, Dirbust, Exposure, GitDumper, PathTraversal, Recon, Secrets,
                        Sqli, WebVulnTriage, Xss)
from .suggesters import (AccessProfile, DynamicSuggester, ExposureProfile, InjectionProfile,
                         MinorityReport, ReconProfile)

# the MANAGERS (agent type 1) - each commissions verified work from the specialists in its lane, or stands
# down. The board, plus the mandated dissent (MinorityReport) which always commissions a divergent angle after
# seeing the board.
SUGGESTERS = [
    ReconProfile(),
    AccessProfile(),
    InjectionProfile(),
    ExposureProfile(),
    MinorityReport(),     # the dissent - always last, always speaks
]

# working agents (agent type 2) - one PROFESSIONAL specialist per security issue; each answers a manager's
# commission with verified results. name -> class
EXECUTORS = {e.name: e for e in (Recon, Dirbust, AccessControl, WebVulnTriage, Sqli, Xss,
                                 PathTraversal, GitDumper, Secrets, Exposure)}

# detect -> exploit escalation: when an executor (e.g. web-vuln-triage) confirms a finding of one of these
# CLASSES, the pipeline spawns the matching exploitation specialist on that target IN THE SAME ROUND, so a
# triaged class doesn't wait a full round to be exploited. Only mappings whose target executor exists are kept.
ESCALATE = {cls: ex for cls, ex in
            {"sqli": "sqli", "xss": "xss", "lfi": "path-traversal", "traversal": "path-traversal"}.items()
            if ex in EXECUTORS}

# the control roles (one each). REVIEWER is a separate oversight org - it monitors the decision and can
# grow the council, but never overrides the head or the plan. ADJUSTER runs after each executor to prune/
# fix the remaining steps with what was just learned.
CONCLUDER = Concluder()
REVIEWER = Reviewer()
PLANNER = Planner()
ADJUSTER = Adjuster()
REPORTER = Reporter()


def executor_manual() -> str:
    """The planner's manual: exactly what each executor does and the tools it has - so steps can be tailored."""
    return "\n".join(f"  - {e.name}: {e.description}\n      tools: {', '.join(sorted(e.tools))}"
                     for e in EXECUTORS.values())


def roster() -> str:
    sug = "\n".join(f"  - {s.name}{' [DISSENT]' if s.dissent else ''}: {s.focus}  -> {', '.join(s.proposes)}"
                    for s in SUGGESTERS)
    exe = "\n".join(f"  - {e.name}: {e.description}" for e in EXECUTORS.values())
    return (f"SUGGESTERS = MANAGERS (each commissions specialists in its lane; the head=concluder prioritizes):\n{sug}\n\n"
            f"EXECUTORS = SPECIALISTS (answer one commission with verified results):\n{exe}\n\n"
            "CONTROL: concluder (council head, prioritizes) | reviewer (separate oversight org: monitors the "
            "decision for the user, can grow the council) | planner (tailors steps) | adjuster (after each "
            "executor: prune/fix the remaining steps) | reporter (final report)")

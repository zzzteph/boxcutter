"""The ORCA loop - pop a task, run its executor, let advisors observe, let ORCA plan the next tasks.

This is the dynamic queue in action: the flow starts with a single recon task and GROWS as results come
in (the planner appends new tasks to the bottom), so the whole run is one ordered, reasoned plan you can
read top to bottom. Deterministic executors do the routine coverage; the LLM planner steers and chains.
"""

from __future__ import annotations

import sys

from . import advisors, planner
from .executors import EXECUTORS
from .state import Task

_MAX_CYCLES = 60          # planner decisions (each is one LLM call); a hard ceiling for predictability


def run(provider, state, args) -> None:
    max_cycles = getattr(args, "max_cycles", None) or _MAX_CYCLES
    runner = args._runner                            # the standalone boxcutter bridge, set by the entrypoint

    # seed: the one action every run starts from
    state.enqueue(Task("recon", {"target": state.base_url}, "initial surface mapping", by="seed"))

    cycles = 0
    while state.queue and cycles < max_cycles:
        task = state.pop()
        executor = EXECUTORS.get(task.action)
        if not executor:
            continue
        task.status = "running"
        sys.stderr.write(f"[orca] cycle {cycles + 1}: {task.action} {state._args_str(task.args)}  "
                         f"<- {task.reason}\n")
        state.plan_add(f"run {task.action} {state._args_str(task.args)}", task.reason, by=task.by, status="run")
        try:
            executor().run(state, task, runner, provider)
            task.status = "done"
        except Exception as exc:  # noqa: BLE001 - one executor failing must not abort the engagement
            task.status = "failed"
            state.note(f"{task.action} failed: {exc}")

        # advisors observe the new state, ORCA plans the next tasks (appended to the bottom of the queue)
        suggestions = advisors.gather(state)
        decision = planner.decide(provider, state, suggestions)
        if decision.get("rationale"):
            state.plan_add(f"plan: {decision['rationale']}", "", by="orca", status="think")
        for s in decision.get("schedule", []):
            state.enqueue(Task(s["action"], s.get("args") or {}, s.get("reason", ""), by="orca"))
        cycles += 1
        if decision.get("stop") and not state.queue:
            break

    # always finish with a report over whatever was verified
    EXECUTORS["report"]().run(state, Task("report", {}), runner, provider)
    print("\n" + state.coverage_report())
    print("\n" + state.plan_render())

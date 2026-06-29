"""orca - an autonomous, queue-driven bug-hunter, standalone and isolated from bob.

Where bob is a fixed team of specialists that hand off through a shared context, orca is a three-level
planner/advisor/executor system built around a DYNAMIC work-queue:

  * ORCA (planner)  - an LLM that, each cycle, reads the state + the advisors' suggestions and decides
                      which executor runs next; it appends new tasks to the bottom of the queue, so the
                      flow grows as results arrive and the whole run is one ordered, reasoned plan.
  * Advisors        - read-only observers of the state that SUGGEST next actions (with a reason and a
                      priority); they never act.
  * Executors       - the working agents that DO one action (recon, fuzz, request battery, sqlmap,
                      exposure, report) and write results back to the state.

orca shares NO code with bob's `agent/` package - it has its own provider, runner, and state - so the
two can be run side by side and compared. It drives the same boxcutter tool layer (that's the toolkit
both use), exposed as `boxcutter orca <target>`.
"""

"""Uniform reasoning / trace helpers shared by EVERY agentic loop (crawlio, logio, prawlio, IRVIN's executors).

The goal is that all AI agents narrate and trace the SAME way, so a run is auditable no matter which agent
produced it:

  * NARRATE   - a system-prompt snippet telling the model to state a one-line WHY before each tool call, so the
                trace carries the reasoning, not just the commands.
  * summarize - a one-line, human-readable summary of what a tool call ACTUALLY returned (error / item count /
                statuses / a landed-page + api-flow count for the visual driver), so a reader sees the OUTCOME
                of each action, not only that it was issued.
  * forward_debug - append --debug to a sub-tool dispatch when the agent itself is running under --debug, so
                the sub-tool streams its own diagnostics (browser-crawl's landed-url, visual-driver's ok/failed
                /flow counts, ...) instead of staying silent inside the agent.

Kept in core - the lowest layer - so both boxcutter/ai/* and boxcutter/irvin/* import it without a cycle.
"""

from __future__ import annotations

import json

# Added to every agent's system prompt. Generic on purpose: each agent keeps its own domain FLOW guidance, but
# the "say WHY before you act" contract is identical everywhere.
NARRATE = (
    "NARRATE - before each tool call, say in ONE short sentence WHY you're making it and what you expect it to "
    "tell you (e.g. 'probing the well-known paths for an API spec', 'opening the account page to fire its "
    "data-load calls', 'the field stayed empty so I'm re-reading the input's coordinate'). One line, then call "
    "the tool - this keeps the run auditable so a reader can follow your reasoning, not just your commands.\n"
)


def summarize(raw: str) -> str:
    """One line describing what a tool's JSON envelope actually yielded, for a --debug trace.

    Handles the visual-driver shape specially (a `state` record + api `flows`) because 'N ok / M failed, K api
    flow(s), on <url>' is exactly the detail that tells you whether a coordinate step worked - far more useful
    there than a bare item count."""
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001 - a non-JSON body is still worth a size hint
        return f"{len(raw)} bytes (non-JSON)"
    if isinstance(env, dict) and env.get("error") and not env.get("data"):
        return f"error/empty: {str(env['error'])[:120]}"
    data = env.get("data") if isinstance(env, dict) else None
    if not isinstance(data, list):
        return "ok"
    if not data:
        return "0 items (nothing found)"
    head = data[0]
    if isinstance(head, dict) and head.get("type") == "state":       # visual-driver reply: state + flows
        flows = sum(1 for d in data if isinstance(d, dict) and d.get("type") != "state")
        return (f"{head.get('actions_ok', '?')} action(s) ok / {head.get('actions_failed', '?')} failed, "
                f"{flows} api flow(s); on {str(head.get('url', ''))[:60]}")
    statuses = sorted({d["status"] for d in data if isinstance(d, dict) and isinstance(d.get("status"), int)})
    sample = head.get("url") if isinstance(head, dict) else (head if isinstance(head, str) else "")
    bits = [f"{len(data)} item(s)"]
    if statuses:
        bits.append("status " + ",".join(str(s) for s in statuses[:6]) + ("…" if len(statuses) > 6 else ""))
    if sample:
        bits.append("e.g. " + str(sample)[:70])
    return "; ".join(bits)


def forward_debug(argv, debug: bool):
    """Return argv with a single --debug appended when `debug` is set and it isn't there already - so an
    in-process sub-tool dispatch streams its OWN stderr diagnostics while the agent is in --debug. A no-op copy
    otherwise. Kept off the cache/trace key by callers, who append it only to the dispatched argv."""
    argv = list(argv)
    if debug and "--debug" not in argv:
        argv.append("--debug")
    return argv

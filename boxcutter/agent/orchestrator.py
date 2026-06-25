"""Orchestrator - runs the agent pipeline over one shared Context.

Sequential by design: producers (discovery/profile/api/exposure) run before consumers (fuzzer/access/
lateral), so a credential or endpoint harvested early is already in the shared Context by the time the
deeper agents run. The `lateral` agent does the final deep re-sweep with every identity gathered so far.
"""

from __future__ import annotations

import sys

from .agents import AGENTS


def run_pipeline(provider, runner, ctx, agent_names, args):
    for name in agent_names:
        agent = AGENTS[name](provider, runner, args)
        agent.say("starting")
        try:
            agent.run(ctx)
        except Exception as exc:  # noqa: BLE001 - one agent failing must not abort the engagement
            agent.say(f"agent error: {exc}")
            ctx.note(f"{name} aborted: {exc}")
    return ctx

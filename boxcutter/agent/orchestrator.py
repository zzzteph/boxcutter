"""Coordinator - an adaptive scheduler, not a fixed pipeline.

Each agent declares a trigger predicate (`should_run`); the coordinator runs only the agents whose
trigger the shared Context satisfies (no API surface -> no api agent; no JS -> no js-analyzer), and
re-sweeps the auth-dependent agents when a credential is harvested mid-run (the late-JWT chain). The
analysis tail (validator -> correlator -> reporter) always runs last over whatever was found.
"""

from __future__ import annotations

from .agents import AGENTS, PIPELINE

_TAIL = ("validator", "correlator", "reporter")     # analysis layer, always last, in this order
_CONSUMERS = ("fuzzer", "access", "lateral")         # benefit from a credential harvested after they ran
_MAX_ROUNDS = 3                                       # times the consumers may re-sweep on new surface/creds


def _surface_sig(ctx):
    s = ctx.surface
    return (len(ctx.identities), sum(len(s.get(k, [])) for k in ("endpoints", "param_urls", "tier1")))


def _keep_alive(ctx, runner):
    """Probe the base before the deep phase; the Runner auto-refreshes the session on a 401."""
    sess = ctx.active_session()
    if sess and ctx.base_url:
        runner(["http-request", ctx.base_url], allowed={"http-request"}, ctx=ctx)


def run_pipeline(provider, runner, ctx, agent_names, args):
    # agent_names None/empty => auto: the run self-selects from the full pipeline via should_run
    if not agent_names:
        agent_names = [cls.name for cls in PIPELINE]
    ran_at = {}

    def run_one(name, note=""):
        agent = AGENTS[name](provider, runner, args)
        if not agent.should_run(ctx):
            agent.say("skipped (trigger not met)")
            ctx.note(f"{name}: skipped - trigger not met")
            if name not in ctx.skipped:
                ctx.skipped.append(name)
            return
        agent.say("starting" + note)
        ran_at[name] = _surface_sig(ctx)
        try:
            agent.run(ctx)
        except Exception as exc:  # noqa: BLE001 - one agent failing must not abort the engagement
            agent.say(f"error: {exc}")
            ctx.note(f"{name} aborted: {exc}")

    body = [n for n in agent_names if n not in _TAIL]
    for name in body:
        run_one(name)

    # keep the session fresh, then ITERATE the consumers until no new credentials/endpoints appear
    _keep_alive(ctx, runner)
    consumers = [n for n in _CONSUMERS if n in body]
    for _ in range(_MAX_ROUNDS):
        grew = [n for n in consumers if n in ran_at and _surface_sig(ctx) != ran_at[n]]
        if not grew:
            break
        for name in grew:
            run_one(name, note=" (re-sweep: new surface/credentials)")

    # honesty: flag thin / likely-SPA coverage so the report can't read "clean" by accident
    s = ctx.surface
    discovered = len(s.get("param_urls", [])) + len(s.get("endpoints", [])) + len(s.get("paths", []))
    if discovered < 5:
        ctx.low_coverage = True
        ctx.coverage_reason = (f"only {discovered} URLs discovered - likely a JS/SPA app, blocked, or small; "
                               f"dynamic content needs the browser-crawl tool (full image)")

    for name in (n for n in _TAIL if n in agent_names):
        run_one(name)
    return ctx

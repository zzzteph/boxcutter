"""ORCA - the LLM planner. Each cycle it reads the state digest + the advisors' suggestions and decides
which executor(s) to schedule next and why. It does NOT call tools (executors do); it only plans.
"""

from __future__ import annotations

import json
import re

from .executors import EXECUTORS, roster

_JSON = re.compile(r"\{.*\}", re.S)

SYSTEM = """You are ORCA, the PLANNER of a three-level autonomous web/API bug-hunter.
Levels: ORCA (you) decide the next actions -> EXECUTORS do the work -> ADVISORS observe and suggest.
You own a dynamic work-queue: each cycle you append the next best actions to the bottom of it.

DOCTRINE:
- The advisors are AGNOSTIC invariants, not bug-specific scanners. Every endpoint must be put through ALL
  of them, no sampling: coverage (fuzz+probe), authz-diff (does the answer change with the caller?),
  mutation (is every client value re-validated - ids, amounts, paths?), reflection (input->output),
  workflow (can an auth/payment step be skipped or its result forged?). Approve coverage/recon/exposure
  until the surface is covered - don't fixate on one bug while endpoints remain untested.
- IDENTITY GATE: cross-tenant IDOR/BOLA cannot be PROVEN with one identity. If the authz-diff advisor asks
  to mint a 2nd identity, schedule it before declaring authorization coverage done.
- Use judgment for CREATIVE chaining: when a finding unlocks a next step (sqli->sqlmap --dump, exposed
  source->mine it, harvested creds->reuse, confirmed IDOR->enumerate the range), schedule the follow-up.
- Prefer the advisors' suggestions; add your own only when they miss something. Never schedule an unknown
  executor. Stop only when the surface is covered by every invariant AND live findings are chased to impact.

AVAILABLE EXECUTORS (action names you may schedule):
%s

Respond with ONLY a JSON object, no prose around it:
{"rationale":"<one line>","stop":false,"schedule":[{"action":"<executor>","args":{...},"reason":"<why>"}]}
Schedule 1-4 actions per cycle. Set "stop":true only when nothing useful remains.""" % roster()


def _parse(text):
    m = _JSON.search(text or "")
    if not m:
        return {}
    try:
        obj = json.loads(m.group(0))
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        return {}


def _render_suggestions(suggestions) -> str:
    if not suggestions:
        return "(no advisor suggestions this cycle)"
    return "\n".join(f"- [{s.priority}] {s.action} {s.args}  <- {s.reason}  ({s.by})" for s in suggestions[:20])


def decide(provider, state, suggestions) -> dict:
    """Return {rationale, stop, schedule:[{action,args,reason}]} - only valid executors kept."""
    user = (f"STATE:\n{state.digest()}\n\nADVISOR SUGGESTIONS (priority 1=highest):\n"
            f"{_render_suggestions(suggestions)}\n\nDecide the next actions. JSON only.")
    try:
        raw = provider.chat(SYSTEM, user, max_tokens=1200)
    except Exception as exc:  # noqa: BLE001 - fall back to the top advisor suggestions if the planner errors
        state.note(f"planner error: {exc} - falling back to advisor suggestions")
        return {"rationale": "planner-fallback", "stop": False,
                "schedule": [{"action": s.action, "args": s.args, "reason": s.reason} for s in suggestions[:3]]}
    obj = _parse(raw)
    sched = [s for s in (obj.get("schedule") or []) if isinstance(s, dict) and s.get("action") in EXECUTORS]
    return {"rationale": obj.get("rationale", ""), "stop": bool(obj.get("stop")), "schedule": sched}

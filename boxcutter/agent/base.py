"""Agent base - an adaptive boxcutter-driving loop with a rich shared doctrine.

Each agent is its own module (its own tools, objective, and the slice of context it reads). The base
gives them a shared brain: the BASE doctrine (mission, lateral/deep-dive, how to use the shared
context, tooling), a tool-calling loop where the model decides the next boxcutter call from the last
result, credential harvesting after every call, and a structured handoff merged back into the shared
Context so the next agent can chain off it.
"""

from __future__ import annotations

import json
import re
import sys

from . import harvest as H
from . import toolref
from .context import Finding

BASE = """You are ONE specialist agent in "bob", an autonomous, adaptive web/API BUG-HUNTING pipeline. You do not
run a fixed script - after every tool result you DECIDE the next best action from what you just learned, and
you pursue leads until you reach demonstrable impact.

# Mission: you are a BUG HUNTER, not a passive scanner
Prove impact with a minimal, NON-DESTRUCTIVE proof of concept:
- BOLA/IDOR: read ONE other user's record and quote a field that proves it isn't yours.
- XSS: land a reflected/stored alert(1)-class payload and show where it executes.
- SQLi: pull one row marker (version()/a username) or a deterministic boolean/time signal.
- BFLA/privesc: reach ONE privileged action as a lower-privileged identity.
Chase each bug to the point a triager would accept it. Hard limits: authorized targets only; NO DoS or
volumetric/credential-stuffing; NO destructive writes (PUT/PATCH/DELETE) unless aggressive mode is ON (the
RULES line in the context tells you); redact secret/PII values to pattern+location in everything you report.

# Go DEEP - lateral movement inside the application
You are not one-pass. Treat every credential, endpoint, parameter, path, or leak as a FOOTHOLD to reach more
of the app, then pivot:
- a harvested JWT/cookie -> walk the WHOLE authenticated surface with it; retry everything that 401'd.
- two identities / tenant or object ids -> reach another user's or another org's data (horizontal), or an
  admin-only action from a normal user (vertical).
- a leak (.git, config, JS, verbose error) -> mine it for new endpoints, hosts, secrets, and how auth/IDs are
  built, then act on what you learn.
- component -> next component: admin -> panel -> exposed .git -> config -> new endpoints/subdomains.
Keep pivoting until you hit real impact or genuinely run out of leads. Depth beats breadth.

# Use the shared context (READ IT FIRST, every turn)
The "Engagement context" block is the LIVE shared state produced by every agent before you:
- BASE url + STACK; APP PROFILE (purpose, roles, key_objects, SENSITIVE_ACTIONS) - this is your test plan;
  ground tests in it instead of generic guesses.
- IDENTITIES - including HARVESTED tokens/cookies (label H*). Use the STRONGEST identity on EVERY request.
- SURFACE (live/params/js/paths/api/endpoints/tier1) and HARVESTED secrets.
- PRIOR HANDOFFS - what each earlier agent found. Build on it; never re-discover what's already there.
Then WRITE everything reusable back (the json block below) so the next agent can chain off you: findings, every
credential/token/cookie under artifacts.tokens, new endpoints under artifacts.endpoints, gaps/leads under
artifacts.notes. If you harvest a credential, reuse it immediately AND record it - that is how bob moves laterally.

# Tooling
Act ONLY through the run_boxcutter tool: pass argv tokens (a boxcutter sub-command + its args), e.g.
["fuzz","https://x/?id=1"]. boxcutter sub-commands only - never shell/docker, never another program. Read each
JSON envelope ({success,kind,data,error}) before the next call; gate on success/data; one target per call.
Exact flags + worked examples for YOUR tools are in the "Tool reference" section below - follow them. boxcutter
has no offline hash-cracker, login brute-forcer, or RCE shell; when a chain needs one, report the lead + the
exact manual next step (do not fake it).

# Finish with a structured handoff
End your turn with a final fenced ```json block (and nothing after it):
{"findings":[{"severity":"High|Medium|Low","title":"...","url":"...","cls":"sqli|xss|bola|bfla|exposure|secret|ssti|lfi|rce-lead|...","evidence":"<=100 chars verbatim, redacted","info":"...","reproduce":["<boxcutter argv tokens>"]}],
 "artifacts":{"tokens":[{"header":"Authorization: Bearer ...  OR  Cookie: session=...","source":"<url>"}],"endpoints":["<url>"],"notes":["lead / coverage note for the next agent"]}}
Only include what you actually observed; use [] when empty."""

_JSON_BLOCK = re.compile(r"```json\s*(\{.*\})\s*```", re.S)


class Agent:
    name = "agent"
    tools: set = set()
    max_steps = 16
    emits_report = False        # reporter prints its final text as THE report (no JSON merge)

    def __init__(self, provider, runner, args):
        self.provider = provider
        self.runner = runner
        self.args = args

    # -- overridable per agent -------------------------------------------
    def objective(self, ctx) -> str:
        return "Do your role."

    def context_block(self, ctx) -> str:
        return ctx.brief()

    # -- helpers ----------------------------------------------------------
    def say(self, msg):
        print(f"[{self.name}] {msg}", file=sys.stderr)

    def llm(self, system, user) -> str:
        try:
            return self.provider.chat(system, user)
        except Exception as exc:  # noqa: BLE001
            self.say(f"llm error: {exc}")
            return ""

    # -- the loop ---------------------------------------------------------
    def run(self, ctx) -> str:
        system = f"{BASE}\n\n## Your role: {self.name}\n{self.objective(ctx)}"
        ref = toolref.reference_for(self.tools)
        if ref:
            system += "\n\n" + ref
        messages = [{"role": "user", "content": f"Engagement context:\n{self.context_block(ctx)}\n\nPerform your role now."}]
        final = ""
        for _ in range(self.max_steps):
            try:
                resp = self.provider.send(system, messages)
            except Exception as exc:  # noqa: BLE001
                self.say(f"provider error: {exc}")
                break
            text, calls = self.provider.parse(resp)
            messages += self.provider.assistant_msg(resp)
            if text.strip():
                final = text
                print(text) if self.emits_report else self.say(text.strip()[:300])
            if not calls:
                break
            results = []
            for c in calls:
                argv = c["argv"]
                self.say("> boxcutter " + " ".join(argv))
                out = self.runner(argv, allowed=self.tools)
                H.harvest(ctx, out, source=(argv[1] if len(argv) > 1 else self.name))
                results.append({"id": c["id"], "output": out})
            messages += self.provider.tool_results(results)
        if not self.emits_report:
            self._merge(ctx, final)
        return final

    # -- structured handoff -> shared context ----------------------------
    def _merge(self, ctx, final):
        m = _JSON_BLOCK.search(final or "")
        if not m:
            ctx.handoffs[self.name] = (final or "").strip()[:200] or "(no structured handoff)"
            return
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            ctx.handoffs[self.name] = "(unparsable handoff)"
            return
        findings = obj.get("findings") or []
        for f in findings:
            ctx.add(Finding(
                self.name, str(f.get("severity", "info")).title(), f.get("title", ""), f.get("url", ""),
                str(f.get("cls", "")).lower(), f.get("info", ""), str(f.get("evidence", ""))[:100],
                f.get("reproduce") or []))
        art = obj.get("artifacts") or {}
        for i, tok in enumerate(art.get("tokens") or []):
            hdr = tok.get("header", "")
            if hdr:
                ctx.add_identity(f"H{i + 1}", ["--header", hdr], tok.get("source", self.name))
        ctx.add_surface("endpoints", art.get("endpoints") or [])
        for n in art.get("notes") or []:
            ctx.note(n)
        prof = obj.get("profile")
        if isinstance(prof, dict):
            ctx.app_profile.update({k: v for k, v in prof.items() if v})
        head = (final.split("```")[0]).strip()[:160]
        ctx.handoffs[self.name] = f"{len(findings)} finding(s). {head}"

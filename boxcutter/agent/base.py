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
from . import knowledge
from .context import Finding
from ..core import capability

BASE = """You are ONE specialist agent in "bob", an autonomous, adaptive web/API BUG-HUNTING pipeline. You do not
run a fixed script - after every tool result you DECIDE the next best action from what you just learned, and
you pursue leads until you reach demonstrable impact.

# Mission: you are a BUG HUNTER, not a passive scanner
Prove impact with a minimal, NON-DESTRUCTIVE proof of concept:
- BOLA/IDOR: read ONE other user's record and quote a field that proves it isn't yours.
- XSS: land a reflected/stored alert(1)-class payload and show where it executes.
- SQLi: pull one row marker (version()/a username) or a deterministic boolean/time signal.
- BFLA/privesc: reach ONE privileged action as a lower-privileged identity.
Chase each bug to the point a triager would accept it - then GO FURTHER: once a bug is confirmed, EXTRACT THE
MAXIMUM non-destructive impact and gather everything that proves full severity. NEVER stop at the first signal.
- SQLi: don't stop at the error - `sqlmap <url>` and enumerate banner / current-user / current-db / --dbs /
  --tables / --columns, then --dump a SMALL sample (read-only) to prove real data access.
- BOLA/IDOR: enumerate the id range ({NUMBERS}) and QUANTIFY how many other users'/orgs' records are reachable;
  quote fields from several to show the scope, not just one.
- exposed .git/source/config: `git-extract` the FULL tree, then mine it for credentials, new endpoints, and how
  auth/ids are built - and immediately act on what you find.
- a leaked credential/token: reuse it across the WHOLE authed surface and report everything it unlocks.
- admin/panel/privileged action: don't stop at reaching the page - perform the actual privileged READ (list
  users, read settings) to prove the access is real.
State the BLAST RADIUS (records / users / tenants / secrets reached) in the finding. Read-extraction is expected
and in-scope; only the destructive-WRITE limit below still holds. Hard limits: authorized targets only; NO DoS or
volumetric/credential-stuffing; NO destructive writes (PUT/PATCH/DELETE) unless aggressive mode is ON (the
RULES line in the context tells you); redact secret/PII values to pattern+location in everything you report.

# Be PRECISE - hunt the logic, don't just fuzz
Fuzzing is a confirmer, not a strategy. First UNDERSTAND the application - what it does, its objects, roles,
and workflows (see APP PROFILE) - then reason about where its logic can break: who can reach what, which id
belongs to whom, which step can be skipped or replayed, which value can be tampered. Form a hypothesis about a
specific problem, then use the smallest tool call to prove it. A targeted `http-request` that returns another
user's record is worth more than a thousand blind `fuzz` payloads. Prefer aimed probes over noise.
Think one step cleverer than the obvious check: probe the undocumented sibling of a documented thing, the
value the client sends that the server shouldn't trust, the corner the developer assumed nobody would test -
and chain a small leak into a big one.

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

# Scope, noise, evidence (binds every agent)
OUT OF SCOPE - do not chase: SSRF/CSRF/open-redirect, authenticated login/OAuth/MFA flows, stateful multi-step
logic (coupon reuse, OTP brute, sequenced checkout), environment/infra (ports, subdomain takeover, CORS).
NEVER report as a finding (noise): missing security headers, clickjacking, CORS wildcards, cookie flags; a
WAF/CDN/bot-challenge/rate-limit that BLOCKS you (Cloudflare "Just a moment", a 403/429, a captcha) - that is a
control WORKING, not a bug; "could not confirm / coverage or visibility limitation / unable to determine" - a
thing you were PREVENTED from testing is COVERAGE, put it in artifacts.notes, never in findings.
EVIDENCE: every finding needs verbatim, <=100-char, redacted evidence; no evidence -> at most [SUGGESTION], never [VULN].
ENTRY MODE (shown in the context): domain = full recon incl subdomains; url = stay on THIS host only, no
subdomain enumeration; endpoint = focus the given endpoint, minimal crawl; spec = drive the documented API from
the spec (swagger-parser/endpoints). The runtime enforces scope - work within it.

# Finish with a structured handoff
End your turn with a final fenced ```json block (and nothing after it):
{"findings":[{"severity":"High|Medium|Low","title":"...","url":"...","cls":"sqli|xss|bola|bfla|exposure|secret|ssti|lfi|rce-lead|...","evidence":"<=100 chars verbatim, redacted","info":"...","reproduce":["<boxcutter argv tokens>"]}],
 "artifacts":{"tokens":[{"header":"Authorization: Bearer ...  OR  Cookie: session=...","source":"<url>"}],"endpoints":["<url>"],"notes":["lead / coverage note for the next agent"]}}
Each `reproduce` MUST be a COMPLETE, self-contained boxcutter argv that reproduces the finding on its own - if
the finding needed auth, include the exact `--header` identity you used, or the reporter's re-run will look
unauthenticated and wrongly discard a real bug. Only include what you actually observed; use [] when empty."""

_JSON_BLOCK = re.compile(r"```json\s*(\{.*\})\s*```", re.S)

# A "finding" that merely describes a control blocking us (WAF/CDN/captcha/rate-limit) or admits it could not
# confirm anything is COVERAGE, not a vulnerability - route it to notes so it never reaches the report.
_COVERAGE_NOISE = re.compile(
    r"(?i)just a moment|cloudflare|captcha|bot[- ]?challenge|\bwaf\b|rate[- ]?limit"
    r"|could not (?:confirm|verify|determine)|unable to (?:confirm|verify|determine|access)"
    r"|coverage[ /]|visibility limitation|rather than a confirmed")


def _is_coverage_noise(f) -> bool:
    blob = " ".join(str(f.get(k, "")) for k in ("title", "info", "evidence"))
    return bool(_COVERAGE_NOISE.search(blob))


def _extract_handoff(text):
    """The agent's structured handoff dict: a fenced ```json block if present, otherwise the last bare
    {...} object carrying findings/artifacts/verdicts/profile. Models routinely emit bare JSON despite the
    doctrine; silently dropping it is what leaves ctx.findings empty -> validator/correlator skip and
    nothing gets verified. raw_decode is brace/string-safe, so braces inside evidence don't trip it."""
    if not text:
        return None
    m = _JSON_BLOCK.search(text)
    if m:
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    dec = json.JSONDecoder()
    best, idx = None, text.find("{")
    while idx != -1:
        try:
            obj, end = dec.raw_decode(text, idx)
        except json.JSONDecodeError:
            idx = text.find("{", idx + 1)
            continue
        if isinstance(obj, dict) and any(k in obj for k in ("findings", "artifacts", "verdicts", "profile")):
            best = obj                       # keep the LAST qualifying object - the handoff is at the end
        idx = text.find("{", max(end, idx + 1))
    return best


def _summary(out):
    """One-line summary of a tool result for --steps."""
    try:
        env = json.loads(out)
    except Exception:  # noqa: BLE001
        return out[:80]
    if not env.get("success"):
        return "FAIL: " + str(env.get("error", ""))[:90]
    data = env.get("data")
    return f"ok kind={env.get('kind')} n={len(data) if isinstance(data, list) else 0}"


class Agent:
    name = "agent"
    tools: set = set()
    max_steps = 16
    emits_report = False        # reporter prints its final text as THE report (no JSON merge)

    def __init__(self, provider, runner, args):
        self.provider = provider
        self.runner = runner
        self.args = args
        # only offer tools whose binary is actually installed in this image, so the agent doesn't
        # burn a round calling a missing sqlmap/screenshot/zap and get an error envelope back.
        self.tools = {t for t in type(self).tools if capability.name_available(t)} or set(type(self).tools)

    # the coordinator skips an agent whose trigger isn't met (no API surface -> no api agent, etc.)
    def should_run(self, ctx) -> bool:
        return True

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

    def system_prompt(self, ctx) -> str:
        """The full assembled prompt for this agent: BASE doctrine + role objective + tool reference
        (its tools only) + judgment rubric (its classes only). The agent .py file holds only the
        objective layer - inspect the whole thing with `boxcutter bob <t> --show-prompts`."""
        system = f"{BASE}\n\n## Your role: {self.name}\n{self.objective(ctx)}"
        ref = toolref.reference_for(self.tools)
        if ref:
            system += "\n\n" + ref
        kb = knowledge.for_agent(self.name)
        if kb:
            system += "\n\n" + kb
        return system

    # -- the loop ---------------------------------------------------------
    def run(self, ctx) -> str:
        ctx.current_agent = self.name
        system = self.system_prompt(ctx)
        mem = self.context_block(ctx)
        followups = ctx.follow_ups_block(self.name)
        if followups:
            mem += "\n\n" + followups
        if getattr(self.args, "steps", False):
            self.say(f"payload: system {len(system)} chars (~{len(system) // 4} tok) "
                     f"+ shared-memory {len(mem)} chars (~{len(mem) // 4} tok)")
        messages = [{"role": "user", "content": f"Engagement context:\n{mem}\n\nPerform your role now."}]
        final, requested, stall, reason = "", set(), 0, "capped"
        for _ in range(self.max_steps):
            try:
                resp = self.provider.send(system, messages)
            except Exception as exc:  # noqa: BLE001
                self.say(f"provider error: {exc}")
                reason = "error"
                break
            text, calls = self.provider.parse(resp)
            messages += self.provider.assistant_msg(resp)
            if text.strip():
                final = text
                print(text) if self.emits_report else self.say(text.strip()[:300])
            if not calls:
                reason = "done"
                break
            fresh = [c for c in calls if tuple(c["argv"]) not in requested]
            results = []
            for c in calls:
                argv = c["argv"]
                requested.add(tuple(argv))
                self.say("> boxcutter " + " ".join(argv))
                out = self.runner(argv, allowed=self.tools, ctx=ctx)
                if getattr(self.args, "steps", False):
                    self.say("  = " + _summary(out))
                H.harvest(ctx, out, source=(argv[1] if len(argv) > 1 else self.name))
                results.append({"id": c["id"], "output": out})
            messages += self.provider.tool_results(results)
            # anti-loop: a round that only re-requests earlier calls means the agent is spinning
            stall = stall + 1 if not fresh else 0
            if stall >= 2:
                self.say("no new actions (repeating prior calls) - stopping early")
                reason = "stalled"
                break
        ctx.stop_reasons[self.name] = reason
        if not self.emits_report:
            self._merge(ctx, final)
        return final

    # -- structured handoff -> shared context ----------------------------
    def _merge(self, ctx, final):
        obj = _extract_handoff(final or "")
        if obj is None:
            ctx.handoffs[self.name] = (final or "").strip()[:200] or "(no structured handoff)"
            return
        findings = obj.get("findings") or []
        for f in findings:
            # a control blocked us / we couldn't confirm -> COVERAGE note, not a finding
            if _is_coverage_noise(f):
                ctx.note("coverage: " + str(f.get("title", "")).strip()[:120]
                         + " (control or visibility limitation - not a finding)")
                continue
            evid = str(f.get("evidence", ""))[:100]
            fobj = ctx.add(Finding(
                self.name, str(f.get("severity", "info")).title(), f.get("title", ""), f.get("url", ""),
                str(f.get("cls", "")).lower(), f.get("info", ""), evid, f.get("reproduce") or []))
            # evidence-binding: a fresh candidate whose evidence isn't in any captured response is unverified
            if fobj.status == "candidate" and evid and (not ctx.evidence_seen(evid) or ctx.in_baseline(evid)):
                fobj.status = "unverified"
        art = obj.get("artifacts") or {}
        for i, tok in enumerate(art.get("tokens") or []):
            hdr = tok.get("header", "")
            if hdr:
                ctx.add_identity(f"H{i + 1}", ["--header", hdr], tok.get("source", self.name))
        ctx.add_surface("endpoints", art.get("endpoints") or [])
        ctx.add_surface("tier1", art.get("tier1") or [])
        for n in art.get("notes") or []:
            ctx.note(n)
        prof = obj.get("profile")
        if isinstance(prof, dict):
            ctx.app_profile.update({k: v for k, v in prof.items() if v})
        # validator verdicts update existing findings in place (confirm / downgrade / drop)
        for v in obj.get("verdicts") or []:
            self._apply_verdict(ctx, v)
        # one-line handoff summary for the next agent (count + a snippet of this agent's own prose)
        head = ((final or "").split("```")[0]).strip()[:160]
        ctx.handoffs[self.name] = (f"{len(findings)} finding(s). {head}").strip()

    def _apply_verdict(self, ctx, v):
        url, title = v.get("url", ""), (v.get("title") or "").strip().lower()
        if not title:
            return
        for g in ctx.findings:
            if g.url == url and (title in g.title.lower() or g.title.lower() in title):
                verdict = v.get("verdict", "")
                ev = str(v.get("evidence", ""))[:100]
                # "confirmed" only sticks if the evidence is actually in a captured response
                if verdict == "confirmed":
                    g.status = "confirmed" if (ev and ctx.evidence_seen(ev) and not ctx.in_baseline(ev)) else "unverified"
                elif verdict in ("downgrade", "downgraded"):
                    g.status = "downgraded"
                elif verdict in ("drop", "dropped"):
                    g.status = "dropped"
                if v.get("severity"):
                    g.severity = v["severity"]
                if ev:
                    g.evidence = ev
                return

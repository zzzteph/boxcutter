"""irvin control roles - the three single agents that drive the spine (one each, not a pool).

  Concluder : collects every suggestion and returns a VERDICT for each (accept/defer/decline) WITH a reason -
              nothing is dropped silently, so deprioritized/declined advice is auditable.
  Planner   : turns the accepted, prioritized conclusions into concrete executor steps, each linked back to
              the suggestion that caused it.
  Reporter  : writes the final report over the verified findings + the decision trail.
"""

from __future__ import annotations

import json
import time
from urllib.parse import urlparse, urlunparse

from ..context import extract_json


class Concluder:
    name = "concluder"
    role = "concluder"

    SYSTEM = (
        "You are the CONCLUDER of IRVIN - the HEAD of the suggester council and the overseer of possible "
        "actions. The profiles each advised what to do next. Collect ALL of their suggestions, merge "
        "duplicates/overlaps, and PRIORITIZE them into one ordered plan, balancing impact, prerequisites "
        "(recon/surface before testing it), and cost - some executors (e.g. dirbust's brute-force, sqli's "
        "extraction runs, spa's browser rendering) are expensive per call; weigh that against what they're "
        "actually yielding. A LOW-YIELD LANE below (running repeatedly with zero findings) is a cost sink even "
        "if it still turns up new surface each time - don't keep feeding an expensive lane on that alone.\n"
        "Weigh the council's TRACK RECORD: a profile whose advice has produced findings has earned priority; "
        "give its advice more weight. And the MINORITY-REPORT (the dissent) is mandatory input - never "
        "auto-decline it; engage with it seriously even when it diverges, because it exists to catch what the "
        "majority misses.\n"
        "You MUST return a verdict for EVERY suggestion id you are given - never drop one silently:\n"
        "  - accept : do it; set its priority (1=highest)\n"
        "  - defer  : not yet (say what must happen first)\n"
        "  - decline: not worth it / out of lane (say why)\n"
        'Reply with ONLY JSON: {"rationale":"<one line: the ordering principle you applied>","verdicts":'
        '[{"ref":"<suggestion id>","verdict":"accept|defer|decline","priority":1,"why":"<one line reason>"}]}')

    def conclude(self, ctx, provider, suggestions) -> dict:
        lines = []
        for r in suggestions:
            d = r.data
            tag = "  <- DISSENT" if r.agent == "minority-report" else ""
            lines.append(f"  {r.id} (from {r.agent}){tag}: {d.get('action')} {d.get('target', '')}  "
                         f"[suggested p{d.get('priority', '?')}]  — {d.get('why', '')}")
        dead = ctx.dead_commissions_render()
        low = ctx.low_yield_render()
        user = (f"LANDSCAPE:\n{ctx.landscape_digest()}\n\nCOUNCIL TRACK RECORD (success earns priority):\n"
                f"{ctx.credibility_render()}\n\nSUGGESTIONS THIS ROUND:\n" + "\n".join(lines) +
                (f"\n\nALREADY ATTEMPTED (ran, returned nothing - decline any repeat of these):\n{dead}" if dead else "") +
                (f"\n\nLOW-YIELD LANES (ran >=2x total, 0 findings so far - weigh cost before accepting more):\n{low}" if low else "") +
                "\n\nReturn a verdict for every id above. JSON only.")
        try:
            raw = provider.chat(self.SYSTEM, user)
        except Exception as exc:  # noqa: BLE001
            # fallback: accept everything in suggested order so the round still proceeds
            verdicts = [{"ref": r.id, "verdict": "accept", "priority": r.data.get("priority", 3),
                         "why": "fallback"} for r in suggestions]
            self._veto_dead(ctx, verdicts)
            return {"rationale": f"concluder error ({exc}) - accepting all in suggested order", "verdicts": verdicts}
        obj = extract_json(raw)
        verdicts = [v for v in (obj.get("verdicts") or []) if isinstance(v, dict) and v.get("ref")]
        seen = {v["ref"] for v in verdicts}
        for r in suggestions:  # guarantee coverage: anything the model forgot is an explicit defer
            if r.id not in seen:
                verdicts.append({"ref": r.id, "verdict": "defer", "priority": 5,
                                 "why": "not addressed by the concluder this round"})
        self._veto_dead(ctx, verdicts)   # deterministic negative memory - the LLM cannot re-accept a dead lead
        return {"rationale": obj.get("rationale", ""), "verdicts": verdicts}

    @staticmethod
    def _veto_dead(ctx, verdicts) -> None:
        """Flip any ACCEPT of an already-attempted-and-empty commission to DECLINE, with a reason. Deterministic
        so the run can never loop on a dead lead even if the LLM keeps accepting it."""
        for v in verdicts:
            if v.get("verdict") != "accept":
                continue
            sug = ctx.get(v.get("ref"))
            if sug and ctx.is_dead_commission(sug.data.get("action"), sug.data.get("target")):
                v["verdict"] = "decline"
                v.pop("priority", None)
                v["why"] = (f"already attempted ({sug.data.get('action')} on "
                            f"{sug.data.get('target') or 'base'}) and it returned nothing - not re-running "
                            "without new evidence")


class Planner:
    name = "planner"
    role = "planner"

    SYSTEM = (
        "You are the PLANNER of IRVIN. You know EXACTLY what every executor agent can and cannot do (their "
        "manual is below). Given the council head's ACCEPTED, prioritized conclusions and the landscape, lay "
        "out the next pipeline STEPS in order and TAILOR each one to its executor: pick the right agent, set "
        "its args, and hand it (1) a precise BRIEF of what to do for THIS target, (2) the RELEVANT CONTEXT it "
        "needs - the specific endpoints/ids/secrets/identities from the landscape, so it doesn't re-discover "
        "them, and (3) what to AVOID - out of scope, known dead ends, noise to skip. Match the job to the "
        "agent's tools; don't ask an agent to do what it can't. Keep each step linked to the suggestion id it "
        "fulfils (`ref`). Drop a conclusion if the landscape shows it isn't actionable yet.\n\n"
        "EXECUTOR MANUAL (who does what, with which tools):\n%s\n\n"
        'Reply with ONLY JSON: {"rationale":"<one line>","done":false,"steps":[{"executor":"<name>","args":{},'
        '"ref":"<suggestion id>","brief":"<what to do for this target>","context":"<relevant facts/pointers '
        'from the landscape>","avoid":"<what NOT to do>","why":"<one line>"}]}. '
        "Set done=true only if there is genuinely nothing worth running.")

    def plan(self, ctx, provider, conclusion, manual, names) -> dict:
        accepted = [v for v in conclusion.get("verdicts", []) if v.get("verdict") == "accept"]
        accepted.sort(key=lambda v: v.get("priority", 5))
        lines = [f"  {v['ref']} (from {ctx.suggester_of(v['ref'])}): {v.get('why', '')} "
                 f"(priority {v.get('priority', '?')})" for v in accepted]
        user = (f"LANDSCAPE:\n{ctx.landscape_digest()}\n\nACCEPTED CONCLUSIONS (priority order):\n" +
                ("\n".join(lines) or "  (none accepted)") + "\n\nLay out the tailored steps. JSON only.")
        raw = ""
        try:
            raw = provider.chat(self.SYSTEM % manual, user)
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"planner provider error: {exc}")
        obj = extract_json(raw)
        steps = [s for s in (obj.get("steps") or []) if isinstance(s, dict) and s.get("executor") in names]
        done = bool(obj.get("done"))
        # resilience: an accepted conclusion must never be lost to a flaky/truncated planner reply (or a
        # spurious done=true). If the head accepted work but the LLM gave no usable steps, schedule that work
        # directly from the suggestions so the run never stalls.
        if not steps and accepted:
            steps = self._fallback_steps(ctx, accepted, names)
            if steps:
                return {"rationale": obj.get("rationale") or "fallback: planner returned no usable plan - "
                        "scheduling the accepted conclusions directly", "done": False, "steps": steps}
        return {"rationale": obj.get("rationale", ""), "done": done, "steps": steps}

    @staticmethod
    def _fallback_steps(ctx, accepted, names) -> list:
        """Deterministic plan from the accepted conclusions: one step per accepted suggestion, executor =
        the suggestion's own action. Guarantees the run never stalls when the planner LLM flubs its JSON."""
        steps = []
        for v in accepted:
            rec = ctx.get(v.get("ref"))
            if not rec:
                continue
            action = rec.data.get("action")
            if action not in names:
                continue
            target = rec.data.get("target") or ctx.base_url
            steps.append({"executor": action, "args": {"url": target} if target else {}, "ref": v.get("ref"),
                          "brief": rec.data.get("why", ""), "context": "", "avoid": "",
                          "why": rec.data.get("why", "")})
        return steps


class Thinner:
    """Runs BETWEEN the planner and the executors so the run never loops on work already done. Two passes:
      1) HARD GATE (deterministic) - drop any step whose (executor, target) already ran this engagement, or is
         duplicated within this plan. Recon included: re-running recon on an endpoint it already mapped just
         re-reads the same links; a genuinely new area is a different target that passes the gate on its own.
      2) LLM PRUNE (conservative, exclude-only) - over the survivors, the model may EXCLUDE any the log shows
         are subsumed/pointless. It can ONLY exclude (never add/modify), so its worst case is over-pruning one
         step, never a loop or invented work."""
    name = "thinner"
    role = "thinner"

    SYSTEM = (
        "You are the THINNER of IRVIN. A deterministic gate has ALREADY removed every action whose "
        "(executor, target) ran before. From the SHORTLIST that remains, your ONLY job is to EXCLUDE actions "
        "the evidence shows are WASTED or SUBSUMED - e.g. a target the log already proved dead/absent, or an "
        "action a prior result makes pointless. You may ONLY exclude; you cannot add, reorder, or modify. Be "
        "CONSERVATIVE: exclude an action only with concrete evidence from the log/landscape; when in doubt, "
        "KEEP it - it is far worse to drop a useful action than to let one extra run.\n"
        'Reply with ONLY JSON: {"rationale":"<one line>","exclude":[{"step":<index>,"reason":"<why it is '
        'wasted/subsumed, citing the evidence>"}]}. Exclude nothing if every action is worth running.')

    def thin(self, ctx, provider, steps) -> dict:
        # 1) deterministic hard gate: exact (executor, target) repeats + intra-plan duplicates. ONE EXCEPTION:
        #    an exploitation lane that already CONFIRMED a finding here earns a single deepening pass (post-ex),
        #    so a 'detect' run doesn't gate the follow-up 'exploit/dump'. That pass is also shielded from the
        #    LLM prune below (its `protected` index), so nothing downstream can quietly drop it either.
        gated, dropped, seen, protected = [], [], set(), set()
        for st in steps:
            ex, tgt = st.get("executor"), ctx.commission_target(st)
            key = (ex, ctx._norm_target(ex, tgt))
            if key in seen:
                dropped.append({"executor": ex, "target": tgt, "by": "gate", "reason": "duplicate within this plan"})
                continue
            seen.add(key)
            if not ctx.was_committed(ex, tgt):
                gated.append(st)
            elif ctx.allows_deepening(ex, tgt):
                st = {**st, "deepening": True}      # tag it: shielded from the LLM prune here AND from the
                protected.add(len(gated))          # adjuster's skip downstream (a post-ex pass, not a re-confirm)
                gated.append(st)
            else:
                dropped.append({"executor": ex, "target": tgt, "by": "gate", "reason": "already ran this engagement"})
        # 2) conservative LLM prune over the survivors (exclude-only) - never touch a protected deepening pass
        kept = []
        excluded = self._llm_exclude(ctx, provider, gated) if gated else {}
        for i, st in enumerate(gated):
            if i in excluded and i not in protected:
                dropped.append({"executor": st.get("executor"), "target": ctx.commission_target(st),
                                "by": "llm", "reason": excluded[i]})
            else:
                kept.append(st)
        deepened = [f"{gated[i].get('executor')} on {ctx.commission_target(gated[i]) or '(base)'}"
                    for i in sorted(protected)]
        return {"kept": kept, "dropped": dropped, "deepened": deepened}

    def _llm_exclude(self, ctx, provider, gated) -> dict:
        """Returns {index: reason} for survivors the model judges wasted. On any error, excludes nothing."""
        lines = [f"  [{i}] {st.get('executor')} {ctx.commission_target(st) or '(base)'}  - "
                 f"{(st.get('brief') or st.get('why') or '').strip()}" for i, st in enumerate(gated)]
        dead = ctx.dead_commissions_render()
        user = (f"LANDSCAPE:\n{ctx.landscape_digest()}\n\nWHAT ALREADY HAPPENED (tail):\n{ctx.recent_trail()}\n\n"
                + (f"ALREADY ATTEMPTED, RETURNED NOTHING:\n{dead}\n\n" if dead else "")
                + "SHORTLIST (exact repeats already removed) - exclude only the wasted/subsumed:\n"
                + "\n".join(lines) + "\n\nJSON only.")
        try:
            raw = provider.chat(self.SYSTEM, user)
        except Exception:  # noqa: BLE001 - on error exclude nothing (never over-prune on a failure)
            return {}
        obj = extract_json(raw)
        out = {}
        for e in (obj.get("exclude") or []):
            if isinstance(e, dict) and isinstance(e.get("step"), int) and 0 <= e["step"] < len(gated):
                out[e["step"]] = str(e.get("reason", ""))[:160]
        return out


class Adjuster:
    """Intermediate controller that runs AFTER each executor. The plan was fixed before the latest results
    came in, so it goes stale mid-round; the adjuster prunes/fixes the REMAINING steps with what was just
    learned - SKIP a step that is now pointless (dead/404 target, already covered, made irrelevant), ADJUST
    one whose target should change, or KEEP it. It never adds steps and never edits results."""
    name = "adjuster"
    role = "adjuster"

    SYSTEM = (
        "You are the ADJUSTER of IRVIN - an intermediate controller that runs AFTER each executor. The plan for "
        "this round was made before the latest results arrived, so some remaining steps may now be a waste. "
        "Using what was JUST learned, decide each REMAINING step:\n"
        "  - skip   : it is now pointless (its target path is dead/404, already covered, or made irrelevant by "
        "a result) - skipping wasted work is the whole point.\n"
        "  - adjust : keep the step but change its args/target (e.g. retarget a dead path to a live one).\n"
        "  - keep   : run it as planned.\n"
        "Do NOT add steps. Be decisive.\n"
        "TWO THINGS YOU MUST NOT DO:\n"
        "  - Do NOT skip a step just because the vulnerability it targets is 'already confirmed'. DETECTION and "
        "EXPLOITATION/POST-EXPLOITATION are different goals - dumping the DB, reading the target file, or digging "
        "into a discovered directory AFTER a confirm is the POINT, not redundant work. A step marked "
        "[POST-EX DEEPENING PASS] is exactly this; KEEP it.\n"
        "  - Do NOT skip a step as 'out of scope' / 'beyond a normal webapp test'. Scope is the operator's "
        "decision, not yours; extraction and post-exploitation are IN scope. Only skip on concrete evidence the "
        "step is now WASTED (dead/404 target, already literally covered by a result, made irrelevant).\n"
        'Reply ONLY JSON: {"rationale":"<one line>","decisions":[{"step":<index>,"action":"keep|skip|adjust",'
        '"args":{},"reason":"<one line>"}]}. Any step you omit defaults to keep.')

    def adjust(self, ctx, provider, last_summary, remaining) -> dict:
        if not remaining:
            return {"rationale": "", "decisions": []}
        lines = [f"  [{i}] {s['executor']} {s.get('args', {})} <- {s.get('ref', '?')}  "
                 f"({s.get('brief') or s.get('why', '')})"
                 + ("  [POST-EX DEEPENING PASS - do not skip]" if s.get("deepening") else "")
                 for i, s in enumerate(remaining)]
        user = (f"LANDSCAPE (updated):\n{ctx.landscape_digest()}\n\nJUST FINISHED:\n{last_summary}\n\n"
                f"REMAINING STEPS this round:\n" + "\n".join(lines) +
                "\n\nDecide keep/skip/adjust for each remaining step. JSON only.")
        try:
            raw = provider.chat(self.SYSTEM, user)
        except Exception as exc:  # noqa: BLE001 - on error, change nothing (keep all)
            return {"rationale": f"adjuster error: {exc}", "decisions": []}
        obj = extract_json(raw)
        return {"rationale": obj.get("rationale", ""), "decisions": obj.get("decisions") or []}


class Reviewer:
    """A SEPARATE oversight org. After the council advises and the head prioritizes, the reviewer monitors
    that decision BEFORE the planner acts. It does NOT top the head: it never edits verdicts or the plan -
    it advises the USER, and (its only lever on the run) it can GROW the council by proposing new suggester
    profiles that join the loop in future rounds."""
    name = "reviewer"
    role = "reviewer"

    SYSTEM = (
        "You are the REVIEWER of IRVIN - a SEPARATE oversight org reporting TO THE USER. You do NOT command "
        "the council or its head and you NEVER override their decision or the plan; you monitor and advise. "
        "The council has advised and the head (concluder) has prioritized; you review that decision BEFORE the "
        "planner acts. Two jobs:\n"
        "1) RECOMMENDATION: tell the user plainly whether this round's decision was sound - did the council "
        "cover what the landscape needs, did the head prioritize sensibly, what blind spot or risk remains.\n"
        "2) COUNCIL GAPS: if a relevant lane of expertise is MISSING (an area the landscape clearly needs that "
        "no current profile covers), propose new suggester profile(s) to add for future rounds. Each must map "
        "to the AVAILABLE EXECUTORS and must not duplicate an existing profile. Propose none if the council is "
        "already adequate - do not invent roles for the sake of it.\n"
        'Reply with ONLY JSON: {"recommendation":"<for the user, 1-2 lines>","decision_good":true,'
        '"new_suggesters":[{"name":"<kebab-name>","profile":"<one line: who they are>","focus":"<their lane>",'
        '"proposes":["<executor>"]}]}')

    def review(self, ctx, provider, suggestions, conclusion, existing_names, executors) -> dict:
        vmap = {v.get("ref"): v for v in conclusion.get("verdicts", [])}
        lines = []
        for r in suggestions:
            v = vmap.get(r.id, {})
            lines.append(f"  {r.id} [{r.agent}] {r.summary} -> {v.get('verdict', '?')} "
                         f"{('p' + str(v.get('priority'))) if v.get('verdict') == 'accept' else ''} "
                         f"({v.get('why', '')})")
        user = (f"LANDSCAPE:\n{ctx.landscape_digest()}\n\nTHE COUNCIL DECISION THIS ROUND:\n" + "\n".join(lines) +
                f"\n\nHEAD'S PRINCIPLE: {conclusion.get('rationale', '')}\n\n"
                f"EXISTING COUNCIL PROFILES: {', '.join(sorted(existing_names))}\n"
                f"AVAILABLE EXECUTORS: {', '.join(executors)}\n\nReview for the user. JSON only.")
        try:
            raw = provider.chat(self.SYSTEM, user)
        except Exception as exc:  # noqa: BLE001
            return {"recommendation": f"(reviewer error: {exc})", "decision_good": True, "new_suggesters": []}
        obj = extract_json(raw)
        specs = []
        for s in (obj.get("new_suggesters") or []):
            name = s.get("name") if isinstance(s, dict) else None
            if not name or name in existing_names or name in {x["name"] for x in specs}:
                continue
            props = [p for p in (s.get("proposes") or []) if p in executors]
            if props:
                specs.append({"name": name, "profile": s.get("profile", ""),
                              "focus": s.get("focus", ""), "proposes": props})
        return {"recommendation": obj.get("recommendation", ""),
                "decision_good": bool(obj.get("decision_good", True)), "new_suggesters": specs[:2]}


class Summarizer:
    """Runs at the END of each round, turning what the executors just DID into a briefing the council reads
    before it decides the next round - the executors_summary -> council edge the pipeline was missing. Two
    parts: a short narrative of what this round actually ESTABLISHED (findings, surface, confirmations - not
    activity for its own sake), and the deterministic COVERAGE MAP of which structural endpoint-families each
    vuln-lane has and has not tested. That turns 'squeeze every endpoint' into a visible, shrinking checklist
    the council owns instead of a hope.

    It ADVISES; it does not command. Coverage is a peer FACT surfaced to the whole council (not a lane that
    competes in the vote), and an owed family the council judges genuinely not worth testing can still be left
    - the summarizer just makes the gap impossible to miss, so the loop keeps working the surface until the
    council is satisfied every family has been squeezed or consciously skipped."""
    name = "summarizer"
    role = "summarizer"

    SYSTEM = (
        "You are the SUMMARIZER of IRVIN. A round just finished; brief the council for the NEXT round in 3-6 "
        "tight lines. Say what the executors actually ESTABLISHED this round (new findings, new surface, "
        "confirmations - not motion for its own sake) and then the single most important thing still UNDONE. "
        "You are given a deterministic COVERAGE MAP of which structural endpoint-families each vuln-lane has vs. "
        "has NOT tested: treat untested APPLICABLE families as the primary unfinished business and name the "
        "concrete ones worth testing next, so the council squeezes the whole surface. If a lane's coverage is "
        "complete, say so plainly so the council can move on. Be specific and short - this is a briefing, not a "
        "report. Plain text, no JSON, no headings.")

    def summarize(self, ctx, provider) -> str:
        coverage = ctx.coverage_render()
        results = [r for r in ctx.trail if r.round == ctx.round and r.kind == "result"]
        res_lines = "\n".join(f"  {r.agent}: {r.summary}"
                              + (f" - {r.rationale}" if r.rationale else "") for r in results) \
            or "  (no executor results this round)"
        health = ctx.command_health_render()
        user = (f"LANDSCAPE:\n{ctx.landscape_digest()}\n\nTHIS ROUND'S EXECUTOR RESULTS:\n{res_lines}\n\n"
                + (coverage or "COVERAGE: no testable families mapped yet")
                + (f"\n\n{health}" if health else "")
                + "\n\nBrief the council for the next round.")
        try:
            return provider.chat(self.SYSTEM, user).strip()
        except Exception as exc:  # noqa: BLE001 - on error, still hand the council the deterministic coverage
            return (coverage or "") + f"\n(summarizer narrative unavailable: {exc})"


class Verifier:
    """Runs after the hunt, before consolidation: an INDEPENDENT existence re-check of EVERY finding, so IRVIN
    can never report a vulnerability on a page that isn't actually there. Executors self-verify, but a
    self-verifying agent can still stand a finding on a URL that never truly existed - a dirbust guess that
    never 200'd, a mirror path sqlmap skipped, an endpoint the model half-invented. This gate re-fetches each
    finding's own location through the same runner the executors use and DROPS only the findings whose page is
    PROVABLY absent (a hard 404/410). It is deliberately conservative: a page that answers with anything else -
    200, 301, 401/403, even 500 - is real and kept, and an unreachable/unparseable response is KEPT-but-flagged
    (a transient network failure must not delete a real finding). Every drop is written to the trail, so a
    removed finding is auditable, never silently gone.

    It fetches the BASE path (scheme://host/path), dropping any injected query/payload the finding URL carries,
    so a real endpoint like `/?id=1' UNION...` is checked as `/` and can't be mistaken for absent."""
    name = "verifier"
    role = "verifier"

    _ABSENT = {404, 410}

    def _check(self, ctx, runner, url) -> tuple[str, str]:
        """(verdict, note) where verdict is 'exists' | 'absent' | 'unconfirmed'. Only 'absent' is a proven
        non-existent page (the one thing we drop)."""
        p = urlparse(url or "")
        if not p.scheme or not p.hostname:
            return "unconfirmed", "no fetchable URL - existence not checked"
        base = urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))
        out = runner(["http-request", base], ctx=ctx, allowed={"http-request"})
        try:
            obj = json.loads(out)
        except Exception:  # noqa: BLE001
            return "unconfirmed", "unparseable response - kept (not proven absent)"
        data = obj.get("data") or []
        status = data[0].get("status") if data and isinstance(data[0], dict) else None
        if status in self._ABSENT:
            return "absent", f"page does not exist (HTTP {status} at {base})"
        if status:
            return "exists", f"exists (HTTP {status})"
        if obj.get("error"):
            return "unconfirmed", f"unreachable: {str(obj.get('error'))[:80]} - kept (not proven absent)"
        return "unconfirmed", "no status - kept (not proven absent)"

    def verify(self, ctx, runner) -> dict:
        fnds = ctx.landscape["findings"]
        kept, dropped, flagged = [], [], []
        for f in fnds:
            verdict, note = self._check(ctx, runner, f.get("url") or "")
            if verdict == "absent":
                dropped.append({"id": f["id"], "title": f["title"], "url": f["url"], "reason": note})
                continue
            if verdict == "unconfirmed":
                f["status"] = "unconfirmed-existence"
                flagged.append({"id": f["id"], "note": note})
            kept.append(f)
        if dropped:
            ctx.landscape["findings"] = kept
        return {"kept": len(kept), "dropped": dropped, "flagged": flagged}


class Consolidator:
    """Runs ONCE after the hunt, right before the reporter. IRVIN files a finding the moment it confirms one,
    so the SAME underlying vulnerability lands as SEVERAL findings - reached through different endpoints, or
    re-confirmed in a later round with different wording (this is exactly how one `where id=$id` behind /?id,
    /bugs/verify.php and /gotoURL.asp became five separate High rows).

    The fix is NOT a heuristic in either direction. Reporting each endpoint separately OVER-counts one bug;
    blindly merging every same-class finding on a host UNDER-counts distinct bugs (two different features that
    both query the one database are two vulnerabilities, not one). Neither guess is acceptable, so this is a
    VERIFICATION step, held to the same evidence bar as every other IRVIN verdict: two findings collapse into
    one ONLY when the evidence PROVES they hit the same sink/object/code path - the merge has to be earned, and
    when it can't be, the findings stay separate."""
    name = "consolidator"
    role = "consolidator"

    _SEV = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    SYSTEM = (
        "You are the CONSOLIDATOR of IRVIN. IRVIN files a finding as soon as it confirms one, so the SAME "
        "underlying vulnerability often appears MORE THAN ONCE - reached through different endpoints, or "
        "re-confirmed in a later round with different wording. Working one CLASS at a time, decide which "
        "findings are PROVABLY the one-and-the-same bug (report them as a SINGLE finding with several affected "
        "locations) and which are genuinely DISTINCT (leave them alone).\n"
        "The bar to MERGE is EVIDENCE, never assumption:\n"
        "  - MERGE only when the evidence shows the SAME sink/object: the same injectable query (same table, "
        "same column count, same WHERE shape), the same file read, the same handler/code path - such that ONE "
        "fix closes all of them. Re-confirmations of the identical endpoint across rounds are the clearest "
        "merge.\n"
        "  - A SHARED error/stack-trace LOCATION across findings on DIFFERENT urls - the SAME source file:line "
        "(e.g. every one reports `/app/index.php:53`), the same DBMS + query shape - is STRONG proof of ONE sink "
        "reached through many routes (a front controller that ignores the path and acts on the query). MERGE "
        "those into one finding with all the routes as affected locations; do NOT report the same "
        "`/app/index.php:53` injection five times because it is reachable via /?id, /verify.php, /eam/vib, ...\n"
        "  - Sharing a host, a database, or merely a vuln CLASS is NOT enough. Two different features that each "
        "query the same DB are TWO bugs; a redirect endpoint and a listing endpoint that both have SQLi are TWO "
        "bugs. If the evidence does not PROVE the same sink/code path, keep them SEPARATE.\n"
        "  - When in doubt, DO NOT merge. Over-merging hides a real bug and is worse than an extra row.\n"
        "A merged finding keeps the HIGHEST severity among its members and lists ALL affected URLs.\n"
        'Reply ONLY JSON: {"rationale":"<one line>","merges":[{"ids":["f1","f4"],"title":"<merged title>",'
        '"severity":"High","reason":"<the shared sink you PROVED, citing the evidence>"}]}. '
        "List a group ONLY to merge it (2+ ids that are provably identical); omit every finding that stays on "
        "its own. Return an empty merges list if nothing is provably one-and-the-same.")

    def _full_evidence(self, ctx, f) -> str:
        """The stored finding evidence is truncated to 120 chars for the digest; recover the fuller text from
        the executor RESULT record that produced it, so equivalence is judged on the real signal (the query
        shape / dumped columns / stack trace), not a clipped preview."""
        best = f.get("evidence", "")
        for r in ctx.trail:
            if r.kind != "result":
                continue
            for hf in (r.data.get("findings") or []):
                if not isinstance(hf, dict):
                    continue
                if (hf.get("title") or "").strip().lower() == f["title"].lower() and (hf.get("url") or "") == f["url"]:
                    ev = str(hf.get("evidence", ""))
                    if len(ev) > len(best):
                        best = ev
        return best[:500]

    def consolidate(self, ctx, provider) -> dict:
        fnds = ctx.landscape["findings"]
        by_cls = {}
        for f in fnds:
            by_cls.setdefault(f["cls"] or "?", []).append(f)
        groups = {c: fs for c, fs in by_cls.items() if len(fs) > 1}
        if not groups:
            return {"merges": [], "rationale": "no class has more than one finding - nothing to consolidate"}

        blocks = []
        for cls, fs in groups.items():
            lines = [f"CLASS `{cls}` ({len(fs)} findings):"]
            for f in fs:
                lines.append(f"  {f['id']} [{f['severity']}] {f['title']}\n"
                             f"      url: {f['url']}\n"
                             f"      evidence: {self._full_evidence(ctx, f)}")
            blocks.append("\n".join(lines))
        user = ("Consolidate the findings below. Only merge findings PROVEN to be the same sink/code path; keep "
                "everything else separate.\n\n" + "\n\n".join(blocks) + "\n\nJSON only.")
        try:
            raw = provider.chat(self.SYSTEM, user)
        except Exception as exc:  # noqa: BLE001 - on any error, change nothing (never over-merge on a failure)
            return {"merges": [], "rationale": f"consolidator error: {exc}"}
        obj = extract_json(raw)
        applied = self._apply(ctx, obj.get("merges") or [])
        return {"merges": applied, "rationale": obj.get("rationale", "")}

    def _apply(self, ctx, merges) -> list:
        """Collapse each PROVEN-equivalent group into its lowest-id member: keep the highest severity, gather
        every affected URL, union the causal refs, and drop the other members from the landscape. A finding id
        may be merged only once (first claim wins), so overlapping groups can't double-remove a record."""
        fnds = ctx.landscape["findings"]
        by_id = {f["id"]: f for f in fnds}
        removed, applied = set(), []
        for m in merges:
            if not isinstance(m, dict):
                continue
            ids = [i for i in (m.get("ids") or []) if i in by_id and i not in removed]
            if len(ids) < 2:
                continue
            members = sorted((by_id[i] for i in ids), key=lambda f: f["id"])
            primary = members[0]
            sev = m.get("severity") or max((mm["severity"] for mm in members),
                                           key=lambda s: self._SEV.get(str(s).lower(), 0))
            affected = []
            for mm in members:
                for u in [mm["url"], *mm.get("affected", [])]:
                    if u and u not in affected:
                        affected.append(u)
            refs = list(primary.get("from") or [])
            for mm in members[1:]:
                refs += [r for r in (mm.get("from") or []) if r not in refs]
                removed.add(mm["id"])
            primary["severity"] = str(sev).title()
            primary["title"] = m.get("title") or primary["title"]
            primary["url"] = affected[0] if affected else primary["url"]
            primary["affected"] = affected
            primary["merged_from"] = [mm["id"] for mm in members]
            primary["from"] = refs
            applied.append({"kept": primary["id"], "ids": [mm["id"] for mm in members],
                            "title": primary["title"], "affected": affected, "reason": str(m.get("reason", ""))[:200]})
        if removed:
            ctx.landscape["findings"] = [f for f in fnds if f["id"] not in removed]
        return applied


class Reporter:
    name = "reporter"
    role = "reporter"

    SYSTEM = (
        "You are the REPORTER of IRVIN. The hunt is over. Using ONLY the VERIFIED findings and the RUN FACTS "
        "given (use those numbers verbatim - never invent findings or counts), produce a GitHub-flavored "
        "MARKDOWN report with EXACTLY these sections, in this order. One TABLE ROW per finding, evidence <=100 "
        "chars and redacted. A finding may already be CONSOLIDATED - reached through several locations that are "
        "the same underlying bug; when a finding lists multiple affected URLs, keep it as ONE row and put every "
        "URL in Location (comma-separated), never split it back into a row per URL. Findings are already "
        "verified; add [SUGGESTION] rows only for concrete leads the "
        "trail shows are worth a human's follow-up. Output the Markdown directly - no preamble, no code fences "
        "around the whole thing.\n\n"
        "TEMPLATE:\n"
        "# Scan Report: <target>\n\n"
        "**Mode:** IRVIN (autonomous)  ·  **Date:** <date>  ·  **Rounds:** <n>\n\n"
        "> ⚠️ Automated analysis - findings need human validation; not all are exploitable in context.\n\n"
        "**Tested:** endpoints <N> · params <N> · hosts <N> · commissions <N> · verified <N>\n\n"
        "## Coverage by stage\n\n"
        "| Stage | Result |\n| --- | --- |\n"
        "| Recon | <surface mapped> |\n"
        "| Content | <hidden paths discovered> |\n"
        "| Exposure | <misconfig / sensitive-file checks> |\n"
        "| Secrets | <secrets found / files scanned> |\n"
        "| Injection | <classes triaged / confirmed> |\n"
        "| Access | <objects × identities, result> |\n"
        "| Exploit | <sqli/lfi/git extraction outcome> |\n\n"
        "## Findings\n\n"
        "| Severity | Title | Location | What is exposed | Reproduce | Evidence |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| High | <title> | `<url>` | <what> | <exact request/step> | <<=100 chars> |\n"
        "| Medium | <...> | | | | |\n"
        "| _Suggestion_ | <title> | | <why worth a human's follow-up> | | |\n\n"
        "(if there are no verified findings, write `None verified.` instead of the table)\n\n"
        "## Not covered\n\n"
        "Authenticated multi-step flows, SSRF/CSRF/open-redirect, environment/infra (ports, CORS, subdomain "
        "takeover), stateful logic — IRVIN is application-layer, single-pass.\n\n"
        "## Summary\n\n"
        "**Vulns** <n> (High <n>, Medium <n>, Low <n>)  ·  **Suggestions** <n>\n\n"
        "## Conclusion\n\n"
        "<1-2 sentences: posture, top risk, highest-impact fix>")

    def report(self, ctx, provider) -> str:
        fnds = ctx.landscape["findings"]
        findings = "\n".join(
            f"- [{f['severity']}|{f['status']}] {f['cls'] or '?'} :: {f['title']} @ {f['url']}"
            + (f"  (SAME BUG also affects: {', '.join(f['affected'][1:])})"
               if len(f.get("affected") or []) > 1 else "")
            + f"\n    evidence: {f['evidence']}  (by {f['by']})" for f in fnds) or "(no verified findings)"
        sev = {}
        for f in fnds:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        cov = {}
        for key, slot in ctx.commissions.items():          # per-executor coverage from the ledger
            ex = key.split("|", 1)[0]
            c = cov.setdefault(ex, {"targets": 0, "findings": 0})
            c["targets"] += 1
            c["findings"] += slot.get("findings", 0)
        cov_lines = "\n".join(f"  {ex}: {d['targets']} target(s), {d['findings']} finding(s)"
                              for ex, d in sorted(cov.items())) or "  (nothing ran)"
        s = ctx.landscape["surface"]
        facts = (f"date={time.strftime('%Y-%m-%d')} rounds={ctx.round} endpoints={len(s['endpoints'])} "
                 f"params={len(s['params'])} hosts={len(s['hosts'])} commissions={len(ctx.commissions)} "
                 f"verified={len(fnds)}\nseverity counts: {sev or '{}'}\nper-executor coverage:\n{cov_lines}")
        user = (f"TARGET: {ctx.target}\n\nRUN FACTS (use these numbers verbatim):\n{facts}\n\n"
                f"VERIFIED FINDINGS:\n{findings}\n\nLANDSCAPE:\n{ctx.landscape_digest()}\n\n"
                f"DECISION TRAIL (tail):\n{ctx.recent_trail(30)}\n\nFill the template exactly.")
        try:
            return provider.chat(self.SYSTEM, user)
        except Exception as exc:  # noqa: BLE001
            return f"(reporter error: {exc})\n\nVerified findings:\n{findings}"

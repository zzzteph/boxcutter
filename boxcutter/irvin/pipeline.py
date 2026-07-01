"""The irvin pipeline - the deterministic spine. Reads the agent registries and runs the same five phases
each round, printing every phase so you can watch what each agent answered and why.

    SUGGEST -> CONCLUDE -> PLAN -> EXECUTE -> (loop) -> REPORT

SUGGEST is a council: the profiles advise in their lanes, then the MINORITY-REPORT (the mandated dissent)
always adds the divergent opinion, having seen the council. CONCLUDE is the council head: it returns a
verdict for every suggestion (accept/defer/decline, with a reason) and weighs each profile's track record.
Convergence: a round where the council stays silent AND nothing new was learned stops the loop (the
dissent alone can keep it alive only while its gambles still produce progress); a round cap is the safety
net. Every decision is written to the machine-parsable trail with causal links, so the final JSON lets any
agent (or you) cross-check why each action happened.
"""

from __future__ import annotations

import json
import sys

from .agents import (ADJUSTER, CONCLUDER, ESCALATE, EXECUTORS, PLANNER, REPORTER, REVIEWER, SUGGESTERS,
                     THINNER, DynamicSuggester, executor_manual)

_W = 64


def _phase(title):
    sys.stderr.write(f"\n{'-' * _W}\n  {title}\n{'-' * _W}\n")


def _escalations(ctx, handoff, producer, scheduled) -> list:
    """detect -> exploit: a confirmed finding of an escalatable class spawns its specialist on the same target,
    THIS round. Skips self-escalation, anything already scheduled, and anything already committed. Returns new
    steps to splice in after the current one."""
    new = []
    for f in (handoff.get("findings") or [])[:8]:
        ex = ESCALATE.get(str(f.get("cls", "")).lower())
        url = f.get("url")
        if not ex or not url or ex == producer:
            continue
        key = (ex, ctx._norm_target(ex, url))
        if key in scheduled or ctx.was_committed(ex, url):
            continue
        scheduled.add(key)
        cls = str(f.get("cls", "")).lower()
        new.append({"executor": ex, "args": {"url": url}, "target": url, "ref": None,
                    "brief": f"Exploit the {cls} that {producer} just confirmed at {url}.",
                    "context": f"{producer} confirmed {cls} at {url}: {str(f.get('evidence', ''))[:120]}",
                    "avoid": "", "why": f"in-round escalation from {producer}'s confirmed {cls}"})
    return new


def _round(n):
    sys.stderr.write(f"\n{'=' * _W}\n  IRVIN | ROUND {n}\n{'=' * _W}\n")


def _fingerprint(ctx) -> int:
    s = ctx.landscape["surface"]
    return (len(s["endpoints"]) + len(s["params"]) + len(s["graphql"]) +
            len(ctx.landscape["findings"]) + len(ctx.landscape["secrets"]))


def _bootstrap_auth(ctx, runner, provider) -> None:
    """Establish an initial session for every identity with stored creds (--creds/--login-url), BEFORE round 1
    - agent-driven, via the same `auth` executor mid-run refresh uses, not a fixed selector-matching call.
    A first login can hit exactly the same ambiguity a refresh can (an identifier-first OIDC/Keycloak flow
    splitting username/password across screens, fields with no id/name, an unexpected extra step) - the
    judgment needed to handle that doesn't disappear just because it's the FIRST login rather than the tenth."""
    labels = sorted({c["label"] for c in ctx._creds.values()})
    for label in labels:
        sys.stderr.write(f"\n  [bootstrap] establishing initial session for identity {label}...\n")
        step = {"executor": "auth", "target": label, "ref": None,
                "brief": f"Establish the FIRST session for identity {label}.", "context": "", "avoid": ""}
        handoff = EXECUTORS["auth"]().run(ctx, step, runner, provider)
        merged = ctx.merge_handoff(handoff, by="auth", refs=[])
        ctx.log_commission("auth", label, handoff, merged)
        ok = bool(ctx.landscape["identities"].get(label))
        sys.stderr.write(f"  [bootstrap] identity {label}: "
                         f"{'session established' if ok else 'FAILED - see notes below'}\n")
        for n in ctx.notes[-3:]:
            sys.stderr.write(f"    note: {n}\n")


def run_agent(name, provider, ctx, runner, brief="", target="") -> bool:
    """Sanity-run ONE agent in isolation - no council/concluder/planner/loop. If `name` is an EXECUTOR,
    commission it directly on the target and print its VERIFIED handoff plus an action/finding summary so you
    can evaluate a single specialist's output and behaviour without the whole pipeline. If it's a SUGGESTER,
    print its one-shot advice. Returns False (and lists the agents) if the name matches neither.

    Credentials, if given, are still bootstrapped first so an agent that needs a session (explore, access
    control, anything authenticated) actually has one - the point is to test the agent as it really runs."""
    if ctx._creds:
        _bootstrap_auth(ctx, runner, provider)

    if name in EXECUTORS:
        _phase(f"SINGLE AGENT :: executor {name}")
        tgt = target or ctx.base_url
        step = {"executor": name, "target": tgt, "ref": None, "avoid": "", "context": "",
                "brief": brief or f"Sanity-run: do your job against {tgt} and hand back verified results."}
        handoff = EXECUTORS[name]().run(ctx, step, runner, provider)
        merged = ctx.merge_handoff(handoff, by=name, refs=[])
        ctx.log_commission(name, ctx.commission_target(step), handoff, merged)
        v = handoff.get("verification", {}) or {}
        findings = handoff.get("findings") or []
        arts = handoff.get("artifacts", {}) or {}
        sys.stderr.write(
            f"\n  {name}: {len(findings)} verified finding(s)  "
            f"[candidates={v.get('candidates', '?')} verified={v.get('verified', '?')} "
            f"dropped={v.get('dropped', '?')}]  endpoints={len(arts.get('endpoints') or [])} "
            f"tokens={len(arts.get('tokens') or [])} notes={len(arts.get('notes') or [])}\n")
        for f in findings:
            sys.stderr.write(f"    [{f.get('severity')}|{f.get('cls')}] {f.get('title')} @ {f.get('url')}\n")
        for n in (arts.get("notes") or [])[:8]:
            sys.stderr.write(f"    note: {n}\n")
        print(json.dumps(handoff, indent=2, ensure_ascii=False))
        return True

    sug = next((s for s in SUGGESTERS if s.name == name), None)
    if sug is not None:
        _phase(f"SINGLE AGENT :: suggester {name}")
        res = sug.suggest(ctx, provider)
        for one in res.get("suggestions") or []:
            sys.stderr.write(f"  [{name}] SUGGEST p{one.get('priority', '?')} | "
                             f"{one.get('action')} {one.get('target', '')}  - {one.get('why', '')}\n")
        if res.get("skip"):
            sys.stderr.write(f"  [{name}] SKIP - {res.get('rationale', '')}\n")
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return True

    sys.stderr.write(f"irvin: no agent named '{name}'.\n  executors:  {', '.join(EXECUTORS)}\n"
                     f"  suggesters: {', '.join(s.name for s in SUGGESTERS)}\n")
    return False


def run(provider, ctx, runner, max_rounds=8) -> None:
    if ctx._creds:
        _bootstrap_auth(ctx, runner, provider)

    council = [s for s in SUGGESTERS if not s.dissent]    # mutable: the reviewer can grow it
    dissent = [s for s in SUGGESTERS if s.dissent]
    known_names = {s.name for s in SUGGESTERS}

    for _ in range(max_rounds):
        ctx.round += 1
        _round(ctx.round)
        fp0 = _fingerprint(ctx)

        # 1 -- SUGGEST: the council speaks (or skips), then the dissent always adds its separate opinion ---
        _phase(f"SUGGEST   (council of {len(council)} + {len(dissent)} dissent)")
        suggestions, council_spoke = [], False
        for s in council:
            res = s.suggest(ctx, provider)
            if res["skip"] or not res["suggestions"]:
                ctx.add_record("suggest", "suggester", s.name, "skip", summary="skip", rationale=res.get("rationale", ""))
                sys.stderr.write(f"  [{s.name}]  SKIP - {res.get('rationale', '')}\n")
                continue
            council_spoke = True
            for one in res["suggestions"]:
                rec = ctx.add_record("suggest", "suggester", s.name, "suggestion",
                                 summary=f"{one.get('action')} {one.get('target', '')}".strip(),
                                 rationale=one.get("why", ""), data=one)
                suggestions.append(rec)
                sys.stderr.write(f"  [{s.name}]  SUGGEST {rec.id} | p{one.get('priority', '?')} | "
                                 f"{one.get('action')} {one.get('target', '')}  - {one.get('why', '')}\n")
        for s in dissent:
            res = s.suggest(ctx, provider, peers=suggestions)        # the dissent sees the council first
            for one in res["suggestions"]:
                rec = ctx.add_record("suggest", "suggester", s.name, "suggestion",
                                 summary=f"{one.get('action')} {one.get('target', '')}".strip(),
                                 rationale=one.get("why", ""), data=one)
                suggestions.append(rec)
                sys.stderr.write(f"  [{s.name}]  DISSENT {rec.id} | p{one.get('priority', '?')} | "
                                 f"{one.get('action')} {one.get('target', '')}  - {one.get('why', '')}\n")

        if not suggestions:
            sys.stderr.write("\n  -> no suggestions at all - stopping.\n")
            break

        # 2 -- CONCLUDE: the head returns a verdict for EVERY suggestion, with a reason -------------------
        _phase("CONCLUDE  (council head)")
        concl = CONCLUDER.conclude(ctx, provider, suggestions)
        verdicts = concl.get("verdicts", [])
        crec = ctx.add_record("conclude", "concluder", "concluder", "prioritization",
                          summary=f"{sum(v['verdict'] == 'accept' for v in verdicts)}/{len(verdicts)} accepted",
                          rationale=concl.get("rationale", ""),
                          refs=[v["ref"] for v in verdicts], data={"verdicts": verdicts})
        sys.stderr.write(f"  [concluder]  principle: {concl.get('rationale', '')}\n")
        for v in sorted(verdicts, key=lambda v: (v.get("verdict") != "accept", v.get("priority", 9))):
            mark = {"accept": "ACCEPT ", "defer": "DEFER  ", "decline": "DECLINE"}.get(v["verdict"], "?      ")
            src = ctx.suggester_of(v["ref"])
            pr = f"p{v.get('priority')}" if v.get("verdict") == "accept" else "  "
            sys.stderr.write(f"     {mark} {pr}  {v['ref']} (from {src})  - {v.get('why', '')}\n")

        # 3 -- REVIEW: a separate oversight org monitors the decision for the user; may grow the council ---
        _phase("REVIEW  (separate oversight org - for you)")
        review = REVIEWER.review(ctx, provider, suggestions, concl, known_names, list(EXECUTORS))
        spawned = []
        for spec in review.get("new_suggesters", []):
            council.append(DynamicSuggester(spec["name"], spec["profile"], spec["focus"], spec["proposes"]))
            known_names.add(spec["name"])
            spawned.append(spec)
        ctx.add_record("review", "reviewer", "reviewer", "review",
                   summary=("decision sound" if review.get("decision_good") else "decision questioned")
                           + (f"; +{len(spawned)} suggester(s)" if spawned else ""),
                   rationale=review.get("recommendation", ""), refs=[crec.id],
                   data={"recommendation": review.get("recommendation"),
                         "decision_good": review.get("decision_good"), "new_suggesters": spawned})
        sys.stderr.write(f"  [reviewer]  for the user: {review.get('recommendation', '')}\n")
        sys.stderr.write(f"  [reviewer]  decision_good={review.get('decision_good')}\n")
        for spec in spawned:
            sys.stderr.write(f"  [reviewer]  + spawned council profile '{spec['name']}' ({spec['focus']}) "
                             f"-> {', '.join(spec['proposes'])}\n")

        # the head's verdict stands (the reviewer never overrides it); only proceed if it accepted something
        if not any(v["verdict"] == "accept" for v in verdicts):
            if spawned:
                sys.stderr.write("\n  -> head accepted nothing, but the reviewer grew the council - "
                                 "continuing so the new profile(s) can weigh in.\n")
                continue
            sys.stderr.write("\n  -> head accepted nothing and the council wasn't grown. Stopping.\n")
            break

        # 4 -- PLAN: accepted conclusions -> ordered executor steps, each linked to its suggestion --------
        _phase("PLAN")
        plan = PLANNER.plan(ctx, provider, concl, executor_manual(), list(EXECUTORS))
        steps = plan.get("steps", [])
        prec = ctx.add_record("plan", "planner", "planner", "plan", summary=f"{len(steps)} step(s)",
                          rationale=plan.get("rationale", ""), refs=[crec.id], data={"steps": steps})
        sys.stderr.write(f"  [planner]  {plan.get('rationale', '')}\n")
        for i, st in enumerate(steps, 1):
            sys.stderr.write(f"     step {i}: {st['executor']} {st.get('args', {})}  "
                             f"<- {st.get('ref', '?')}  - {st.get('why', '')}\n")
            if st.get("brief"):
                sys.stderr.write(f"         do:      {st['brief']}\n")
            if st.get("context"):
                sys.stderr.write(f"         context: {st['context']}\n")
            if st.get("avoid"):
                sys.stderr.write(f"         avoid:   {st['avoid']}\n")
        if plan.get("done") or not steps:
            sys.stderr.write("\n  -> planner: nothing actionable to schedule. Stopping.\n")
            break

        # 4b -- THIN: drop actions already done (deterministic gate) + a conservative LLM prune of subsumed ones
        _phase("THIN")
        tres = THINNER.thin(ctx, provider, steps)
        for d in tres["dropped"]:
            sys.stderr.write(f"  [thinner] SKIP {d['executor']} {d['target'] or '(base)'}  - {d['by']}: {d['reason']}\n")
        if tres["dropped"]:
            ctx.add_record("plan", "thinner", "thinner", "adjustment",
                           summary=f"{len(tres['dropped'])} already-done action(s) thinned",
                           rationale="; ".join(f"{d['executor']} {d['target']} [{d['by']}]" for d in tres["dropped"][:6]),
                           refs=[prec.id], data={"dropped": tres["dropped"]})
        steps = tres["kept"]
        if not steps:
            sys.stderr.write("\n  -> thinner: every planned action was already done - nothing new to run. Stopping.\n")
            break
        sys.stderr.write(f"  [thinner] {len(steps)} action(s) kept\n")

        # 5 -- EXECUTE: run each step; spawn in-round escalations from confirmed leads; the ADJUSTER then
        #      prunes/fixes the rest with what was just learned --------------------------------------------
        _phase("EXECUTE")
        i = 0
        scheduled = {(s["executor"], ctx._norm_target(s["executor"], ctx.commission_target(s))) for s in steps}
        while i < len(steps):
            st = steps[i]
            ref = st.get("ref")
            src = ctx.suggester_of(ref) if ref else ("escalation" if st.get("target") else "?")
            sys.stderr.write(f"\n  > step {i + 1}/{len(steps)} | {st['executor']}  (fulfils {ref} from {src})\n")
            handoff = EXECUTORS[st["executor"]]().run(ctx, st, runner, provider)
            refs = [prec.id] + ([ref] if ref else [])
            merged = ctx.merge_handoff(handoff, by=st["executor"], refs=refs)
            ctx.log_commission(st["executor"], ctx.commission_target(st), handoff, merged)   # negative memory
            v = handoff.get("verification", {})
            nf = len(handoff.get("findings") or [])
            dropped = v.get("dropped_titles") or []
            xrec = ctx.add_record("execute", "executor", st["executor"], "result",
                       summary=f"{nf} verified finding(s)",
                       rationale=(f"verified {v.get('verified', '?')}/{v.get('candidates', '?')} candidate(s); "
                                  f"dropped {v.get('dropped', 0)} unverified"
                                  + (f": {', '.join(dropped)}" if dropped else "")), refs=refs, data=handoff)
            ep_dead = v.get("endpoints_dropped", 0)
            ep_note = (f", paths kept={v.get('endpoints_kept', 0)} dead={ep_dead}"
                       if (v.get("endpoints_kept") or ep_dead) else "")
            sys.stderr.write(
                f"  OK {st['executor']}: {nf} verified  [candidates={v.get('candidates', '?')} "
                f"verified={v.get('verified', '?')} dropped={v.get('dropped', '?')}{ep_note}]  <- {ref}\n")

            # ESCALATE: a confirmed exploitable class spawns its specialist on the same target, this round
            escalated = _escalations(ctx, handoff, st["executor"], scheduled)
            if escalated:
                ctx.add_record("execute", "escalator", "escalator", "adjustment",
                               summary=f"+{len(escalated)} in-round escalation(s)",
                               rationale="confirmed exploitable class -> matching specialist, same round",
                               refs=[xrec.id], data={"escalations": [s["why"] for s in escalated]})
                for s in escalated:
                    sys.stderr.write(f"  [escalator] + {s['executor']} on {s['target']}  - {s['why']}\n")

            # ADJUSTER: re-evaluate the REMAINING (previously-planned) steps with what this executor just learned
            remaining = steps[i + 1:]
            kept_rest = remaining
            if remaining:
                last_summary = (f"{st['executor']}: {nf} verified finding(s); "
                                f"dead paths: {', '.join(v.get('dead_paths') or []) or '-'}")
                adj = ADJUSTER.adjust(ctx, provider, last_summary, remaining)
                decisions = {d.get("step"): d for d in adj.get("decisions", []) if isinstance(d, dict)}
                kept_rest, changes = [], []
                for idx, s in enumerate(remaining):
                    d = decisions.get(idx) or {}
                    action = d.get("action", "keep")
                    if action == "skip":
                        changes.append(f"SKIP [{idx}] {s['executor']} {s.get('args', {})} - {d.get('reason', '')}")
                        continue
                    if action == "adjust" and d.get("args"):
                        s = {**s, "args": d["args"]}
                        changes.append(f"ADJUST [{idx}] {s['executor']} -> {d['args']} - {d.get('reason', '')}")
                    kept_rest.append(s)
                if changes:
                    ctx.add_record("execute", "adjuster", "adjuster", "adjustment",
                                   summary=f"{len(remaining) - len(kept_rest)} skipped, "
                                           f"{sum(c.startswith('ADJUST') for c in changes)} adjusted",
                                   rationale=adj.get("rationale", ""), refs=[xrec.id], data={"changes": changes})
                    sys.stderr.write(f"  [adjuster] {adj.get('rationale', '')}\n")
                    for c in changes:
                        sys.stderr.write(f"     - {c}\n")
            # escalations run BEFORE the previously-planned remainder (exploit the fresh lead first)
            steps = steps[:i + 1] + escalated + kept_rest
            i += 1

        # convergence: the council is silent AND the round learned nothing new
        if not council_spoke and _fingerprint(ctx) == fp0:
            sys.stderr.write("\n  -> council silent and no new ground gained - converged. Stopping.\n")
            break

    # 6 -- REPORT ----------------------------------------------------------------------------------------
    _phase("REPORT")
    report = REPORTER.report(ctx, provider)
    ctx.add_record("report", "reporter", "reporter", "report", summary="final report", data={"text": report})
    print(report)

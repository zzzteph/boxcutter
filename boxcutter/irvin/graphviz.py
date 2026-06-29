"""Graphviz DOT for IRVIN. Two views:

  - dot()         : the STATIC pipeline (built from the live agent registries, so it never drifts). Print
                    with `boxcutter irvin --graphviz`.
  - trace_dot(ctx): what ACTUALLY happened in a run - the decision trail as a causal graph (rounds,
                    suggestions, verdicts, plans, results, findings). Emit at the end with `--graph`.

Render either yourself, e.g.:  boxcutter irvin --graphviz | dot -Tpng -o irvin.png
"""

from __future__ import annotations

from .agents import EXECUTORS, SUGGESTERS


def _nid(name: str) -> str:
    return name.replace("-", "_").replace(".", "_")


def _esc(s: str, n: int = 40) -> str:
    """Escape one field for a DOT label (collapse newlines, escape backslashes/quotes, truncate)."""
    s = str(s or "").replace("\n", " ")
    if len(s) > n:
        s = s[:n] + "..."
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _lbl(*fields) -> str:
    """Join already-escaped fields into a multi-line DOT label (\\n is a DOT line break)."""
    return "\\n".join(f for f in fields if f)


def dot() -> str:
    council = [s for s in SUGGESTERS if not s.dissent]
    dissent = [s for s in SUGGESTERS if s.dissent]
    L = []
    a = L.append

    a("digraph irvin {")
    a('  rankdir=TB; fontname="Helvetica"; labelloc=t;')
    a('  label="IRVIN - pipeline bug-hunter (council + separate oversight org)";')
    a('  node [fontname="Helvetica", shape=box, style="rounded,filled", fillcolor="#eef3fb", color="#3b5b92"];')
    a('  edge [fontname="Helvetica", color="#3b5b92"];')
    a('  start [shape=oval, fillcolor="#d9ead3", label="boxcutter irvin <target>"];')

    # ---- the round ----
    a('  subgraph cluster_round {')
    a('    label="ROUND (repeats until convergence / max-rounds)"; style="rounded,dashed"; color="#888";')

    # 1 SUGGEST
    a('    subgraph cluster_suggest {')
    a('      label="1 - SUGGEST (council)"; style="rounded,filled"; fillcolor="#f6f6f6"; color="#999";')
    for s in council:
        a(f'      {_nid(s.name)} [label="{s.name}"];')
    a('      _dynamic [label="...dynamic profiles\\n(spawned by reviewer)", '
      'style="rounded,filled,dashed", fillcolor="#fff2cc"];')
    for s in dissent:
        a(f'      {_nid(s.name)} [label="{s.name}\\n(DISSENT - always speaks)", '
          'fillcolor="#fde9e9", color="#a33"];')
    a('    }')

    # 2 CONCLUDE / 3 REVIEW / 4 PLAN
    a('    conclude [label="2 - CONCLUDE (council head)\\nverdict per suggestion:\\n'
      'accept/defer/decline +reason\\nweighs track record", fillcolor="#dbe7c9"];')
    a('    review [label="3 - REVIEW (separate oversight org)\\nmonitors decision FOR THE USER\\n'
      'never overrides - can grow council", fillcolor="#fff2cc", color="#bf9000"];')
    a('    plan [label="4 - PLAN (planner)\\nknows every executor;\\n'
      'tailors brief+context+avoid", fillcolor="#dbe7c9"];')

    # 5 EXECUTE
    a('    subgraph cluster_exec {')
    a('      label="5 - EXECUTE (do + self-verify)"; style="rounded,filled"; fillcolor="#f6f6f6"; color="#999";')
    for name in EXECUTORS:
        a(f'      e_{_nid(name)} [label="{name}"];')
    a('    }')
    a('  }')

    # ---- terminals + store ----
    a('  report [shape=oval, fillcolor="#d9ead3", label="6 - REPORT (reporter)"];')
    a('  user [shape=note, fillcolor="#fde9e9", color="#a33", label="USER\\n(recommendations + trail)"];')
    a('  ctx [shape=cylinder, fillcolor="#e6e6e6", color="#555", '
      'label="CONTEXT\\nlandscape + append-only TRAIL\\n(uniform records, causal refs)"];')

    # ---- flow ----
    first_sug = _nid((council or dissent)[0].name)
    first_exe = f"e_{_nid(next(iter(EXECUTORS)))}"
    a(f'  start -> {first_sug} [lhead=cluster_suggest];')
    for s in council + dissent:
        a(f'  {_nid(s.name)} -> conclude;')
    a('  conclude -> review -> plan;')
    a(f'  plan -> {first_exe} [lhead=cluster_exec];')
    a(f'  {first_exe} -> report [ltail=cluster_exec, label="converged"];')
    a(f'  {first_exe} -> {first_sug} [ltail=cluster_exec, lhead=cluster_suggest, '
      'label="next round\\n(enriched landscape)", style=dashed, constraint=false];')
    a('  report -> user [style=dashed];')

    # oversight org's two non-authoritative levers
    a('  review -> user [label="recommendation:\\nwas the decision good?", style=dashed, color="#bf9000", '
      'fontcolor="#bf9000"];')
    a('  review -> _dynamic [label="spawn profile\\n(joins next round)", style=dashed, color="#bf9000", '
      'fontcolor="#bf9000", constraint=false];')

    # context read/writes
    for n in ("conclude", "plan", "review"):
        a(f'  {n} -> ctx [style=dotted, color="#777", arrowhead=none];')
    a(f'  {first_exe} -> ctx [ltail=cluster_exec, style=dotted, color="#777", arrowhead=none, '
      'label="findings + new surface"];')

    # ---- causal trail legend ----
    a('  subgraph cluster_trail {')
    a('    label="TRAIL - causal chain (cross-checkable)"; style="rounded,filled"; fillcolor="#fbfbf0"; color="#bbb";')
    a('    t_s [label="suggestion s{r}.{n}"];')
    a('    t_c [label="verdict c{r}.{n}", fillcolor="#dbe7c9"];')
    a('    t_p [label="plan p{r}.{n}", fillcolor="#dbe7c9"];')
    a('    t_x [label="result x{r}.{n} -> finding f{n}"];')
    a('    t_s -> t_c -> t_p -> t_x [label="refs", color="#999", fontcolor="#999"];')
    a('  }')

    a("}")
    return "\n".join(L)


# node style per trail record kind: (fillcolor, color, shape)
_KIND_STYLE = {
    "suggestion": ("#eef3fb", "#3b5b92", "box"),
    "prioritization": ("#dbe7c9", "#38761d", "box"),
    "review": ("#fff2cc", "#bf9000", "box"),
    "plan": ("#dbe7c9", "#38761d", "box"),
    "result": ("#eef3fb", "#3b5b92", "box"),
    "adjustment": ("#fce5cd", "#b45f06", "box"),
    "report": ("#d9ead3", "#38761d", "oval"),
}
_VERDICT_EDGE = {
    "accept": 'color="#38761d"',
    "defer": 'color="#999999", style=dashed',
    "decline": 'color="#a33333", style=dotted',
}


def _node_label(rec) -> str:
    if rec.kind == "suggestion":
        d = rec.data
        return _lbl(_esc(f"{rec.id}  {rec.agent}"), _esc(f"{d.get('action')} {d.get('target', '')}"))
    if rec.kind == "prioritization":
        return _lbl(_esc(f"{rec.id}  concluder"), _esc(rec.summary))
    if rec.kind == "review":
        good = "sound" if rec.data.get("decision_good") else "questioned"
        spawned = len(rec.data.get("new_suggesters") or [])
        return _lbl(_esc(f"{rec.id}  reviewer"), _esc(good + (f" (+{spawned} profile)" if spawned else "")))
    if rec.kind == "plan":
        return _lbl(_esc(f"{rec.id}  planner"), _esc(rec.summary))
    if rec.kind == "result":
        v = rec.data.get("verification") or {}
        return _lbl(_esc(f"{rec.id}  {rec.agent}"), _esc(rec.summary),
                    _esc(f"verify {v.get('raw', '?')}->{v.get('kept', '?')}"))
    if rec.kind == "adjustment":
        return _lbl(_esc(f"{rec.id}  adjuster"), _esc(rec.summary))
    if rec.kind == "report":
        return _esc(f"{rec.id}  reporter")
    return _esc(f"{rec.id} {rec.agent}")


def trace_dot(ctx) -> str:
    """Render what ACTUALLY happened in the run: the context trail as a causal graph. Suggestions -> the
    head's verdict (edge colored accept/defer/decline) -> plan -> result -> finding. Skips are omitted for
    clarity (they're in the full --trail JSON)."""
    L = []
    a = L.append
    a("digraph irvin_trace {")
    a('  rankdir=LR; fontname="Helvetica"; labelloc=t;')
    a(f'  label="IRVIN run trace - {_esc(ctx.target, 60)}  ({ctx.round} round(s), '
      f'{len(ctx.landscape["findings"])} finding(s))";')
    a('  node [fontname="Helvetica", shape=box, style="rounded,filled"];')
    a('  edge [fontname="Helvetica", color="#3b5b92"];')

    # suggestion id -> verdict (to colour the suggestion->conclusion edges)
    verdict = {}
    for rec in ctx.trail:
        if rec.kind == "prioritization":
            for v in rec.data.get("verdicts", []):
                verdict[v.get("ref")] = v.get("verdict")

    # nodes, grouped by round
    drawn = set()
    for rd in sorted({r.round for r in ctx.trail if r.round}):
        a(f'  subgraph cluster_r{rd} {{ label="round {rd}"; style="rounded,dashed"; color="#999";')
        for rec in ctx.trail:
            if rec.round != rd or rec.kind == "skip":
                continue
            fill, col, shape = _KIND_STYLE.get(rec.kind, ("#eeeeee", "#777", "box"))
            if rec.kind == "suggestion" and rec.agent == "minority-report":
                fill, col = "#fde9e9", "#a33333"      # the dissent stands out
            a(f'    {_nid(rec.id)} [label="{_node_label(rec)}", fillcolor="{fill}", color="{col}", shape={shape}];')
            drawn.add(rec.id)
        a("  }")

    # finding nodes
    for f in ctx.landscape["findings"]:
        a(f'  fnd_{_nid(f["id"])} [shape=note, fillcolor="#fde9e9", color="#a33333", '
          f'label="{_lbl(_esc(f["id"] + "  " + f["severity"]), _esc(f["title"]))}"];')

    # causal edges: cause (ref) -> effect (record)
    for rec in ctx.trail:
        if rec.kind == "skip":
            continue
        for ref in rec.refs:
            if ref not in drawn:
                continue
            style = ""
            if rec.kind == "prioritization":            # suggestion -> head verdict, coloured by outcome
                style = " [" + _VERDICT_EDGE.get(verdict.get(ref, ""), 'color="#3b5b92"') + "]"
            a(f"  {_nid(ref)} -> {_nid(rec.id)}{style};")

    # result -> finding it produced
    for rec in ctx.trail:
        if rec.kind != "result":
            continue
        for fd in rec.data.get("findings", []):
            title, url = (fd.get("title") or "").strip().lower(), fd.get("url", "")
            for f in ctx.landscape["findings"]:
                if f["title"].lower() == title and f["url"] == url:
                    a(f'  {_nid(rec.id)} -> fnd_{_nid(f["id"])} [color="#a33333"];')
                    break

    a("}")
    return "\n".join(L)

"""Graphviz DOT for IRVIN's run views:

  - trace_dot(ctx)  : what ACTUALLY happened in a run - the decision trail as a causal graph (rounds,
                      suggestions, verdicts, plans, results, findings). Emit at the end with `--graph`.
  - actions_dot(ctx): the narrower per-step timeline (plan -> thin -> execute -> escalate -> adjust).
                      Emit with `--actions`.

Render either yourself, e.g.:  boxcutter irvin <target> --graph out.dot && dot -Tpng out.dot -o irvin.png
"""

from __future__ import annotations


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


# node fill/border for the actions view, keyed by the acting role
_ACTION_STYLE = {
    "planner": ("#dbe7c9", "#38761d"), "thinner": ("#fce5cd", "#b45f06"),
    "executor": ("#eef3fb", "#3b5b92"), "escalator": ("#fff2cc", "#bf9000"),
    "adjuster": ("#fce5cd", "#b45f06"),
}


def _action_label(rec) -> str:
    tag = {"planner": "PLAN", "thinner": "THIN", "escalator": "ESCALATE", "adjuster": "ADJUST"}.get(rec.agent)
    if tag:
        return _lbl(tag, _esc(rec.summary))
    if rec.kind == "result":                                   # an executor ran
        v = rec.data.get("verification") or {}
        return _lbl(_esc(rec.agent), _esc(rec.summary),
                    _esc(f"verify {v.get('verified', '?')}/{v.get('candidates', '?')}"))
    return _lbl(_esc(rec.agent), _esc(rec.summary))


def actions_dot(ctx) -> str:
    """What the engine DID: per round, the decision steps run (plan -> thin -> execute -> escalate -> adjust)
    AND the concrete tool COMMANDS carried out that round (from the ledger - `subfinder`, `dirb`, `sqlmap`, ...),
    with the findings each step produced. A visual walkthrough of the whole run. Emit with
    `boxcutter irvin --actions`."""
    def is_action(r):
        return (r.phase == "plan" and r.kind in ("plan", "adjustment")) or r.phase == "execute"

    L = []
    a = L.append
    a("digraph irvin_actions {")
    a('  rankdir=TB; fontname="Helvetica"; labelloc=t;')
    a(f'  label="IRVIN actions - {_esc(ctx.target, 60)}  ({ctx.round} round(s), '
      f'{len(ctx.ledger)} tool call(s), {len(ctx.landscape["findings"])} finding(s))";')
    a('  node [fontname="Helvetica", shape=box, style="rounded,filled"];')
    a('  edge [fontname="Helvetica", color="#666"];')

    prev = None
    rounds = sorted({r.round for r in ctx.trail if r.round and is_action(r)}
                    | {e["round"] for e in ctx.ledger if e.get("round")})
    for rd in rounds:
        a(f'  subgraph cluster_a{rd} {{ label="round {rd}"; style="rounded,dashed"; color="#999";')
        for rec in [r for r in ctx.trail if r.round == rd and is_action(r)]:
            role = rec.agent if rec.agent in _ACTION_STYLE else rec.role
            fill, col = _ACTION_STYLE.get(role, ("#eeeeee", "#777"))
            a(f'    {_nid(rec.id)} [label="{_action_label(rec)}", fillcolor="{fill}", color="{col}"];')
            if prev:
                a(f'    {_nid(prev)} -> {_nid(rec.id)};')     # sequential timeline across the whole run
            prev = rec.id
        # the concrete tool COMMANDS carried out this round (from the ledger), chained in order they ran
        cmds = [e for e in ctx.ledger if e.get("round") == rd]
        cprev = None
        for j, e in enumerate(cmds):
            cid = f"cmd_{rd}_{j}"
            a(f'    {cid} [label="{_lbl(_esc(e.get("tool", ""), 22), _esc(e.get("target", ""), 34))}", '
              f'shape=box, style=filled, fillcolor="#f6f6f6", color="#aaa", fontsize=9];')
            if cprev:
                a(f'    {cprev} -> {cid} [style=dotted, color="#bbb", arrowsize=0.6];')
            cprev = cid
        a("  }")

    for f in ctx.landscape["findings"]:
        a(f'  fa_{_nid(f["id"])} [shape=note, fillcolor="#fde9e9", color="#a33333", '
          f'label="{_lbl(_esc(f["id"] + "  " + f["severity"]), _esc(f["title"]))}"];')
    for rec in ctx.trail:
        if rec.kind != "result":
            continue
        for fd in rec.data.get("findings", []):
            title, url = (fd.get("title") or "").strip().lower(), fd.get("url", "")
            for f in ctx.landscape["findings"]:
                if f["title"].lower() == title and f["url"] == url:
                    a(f'  {_nid(rec.id)} -> fa_{_nid(f["id"])} [color="#a33333"];')
                    break

    a("}")
    return "\n".join(L)

"""Compile a UI-authored node graph into a boxcutter workflow spec.

A custom workflow is a graph of TOOL boxes wired producer -> consumer: an edge means "run the downstream tool on
the URLs the upstream one produced" (an in-process ``for_each`` over the engine's ``| urls`` projection). The
result is an ordinary workflow spec dict — the SAME shape the YAML library uses (``{name, input, output, steps}``)
— which we store as JSON text. JSON is a subset of YAML, so the engine's ``yaml.safe_load`` parses it verbatim
when the file is dropped into a ``BOXCUTTER_WORKFLOWS`` dir on the runner (see docs/workflow-builder-design.md).

Kept deliberately framework-free (json + a baked tool-kind map) so it is trivially unit-testable and the server
never has to import the engine. TOOL_KIND mirrors each tool module's ``KIND`` in ``boxcutter/tools/*`` — the
engine is the source of truth; regenerate this map if a tool's kind changes."""
from __future__ import annotations

import json
import re
import shlex

# tool name -> output kind, mirrored from the engine registry (boxcutter/tools/*.KIND).
#   findings  -> issues; a terminal box (can't feed a downstream box)
#   urls      -> a list of URL/host strings; chains cleanly
#   items/... -> a list (strings, or dicts with a url); chains via the engine's `| urls` projection
TOOL_KIND: dict[str, str] = {
    "api-map": "findings", "blind-oracle": "findings", "bola-walk": "findings",
    "browser-actions": "items", "browser-login": "items", "dirb": "findings", "dirsearch": "findings",
    "dns-brute": "urls", "dnsx": "urls", "fuzz": "findings", "git-extract": "findings",
    "graphql-audit": "findings", "graphql-detect": "urls", "harvest": "items", "http-request": "items",
    "httpx": "items", "js-endpoints": "items", "js-files": "urls", "extract-domains": "urls",
    "katana-crawl": "urls", "liveless": "items",
    "mass-assign": "findings",
    "nmap": "endpoints", "nuclei": "findings", "nuclei-dast": "findings",
    "path-bust": "findings", "path-fuzz": "findings",
    "ping-scan": "urls", "scan-secrets": "findings", "screenshot": "screenshots", "smart-enum": "items",
    "sqlmap": "findings", "subfinder": "urls", "swagger-endpoints": "urls", "swagger-parser": "items",
    "swagger-specs": "urls", "vision-verify": "findings", "visual-driver": "items", "wayback": "urls",
    "wayback-domains": "urls", "zap-crawl": "urls", "zap-scan-full": "findings",
    "zap-scan-openapi": "findings", "zap-scan-url": "findings",
    # flow-control pseudo-tools (not real binaries): handled specially by the compiler, not run as a tool.
    "aggregate": "urls", "filter": "urls", "limit": "urls", "hosts": "urls",
}
_FLOW_TOOLS = {"aggregate", "filter", "limit", "hosts"}
# builder box -> (real engine tool, extra opt-arg forwarded to the binary). Lets a box be a preset of another
# tool without the engine needing a new module: nuclei-dast = nuclei with the binary's native `-dast` flag.
_TOOL_ALIAS = {"nuclei-dast": ("nuclei", "-dast")}
_VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
_MAX_NODES = 50

# a per-box CONDITION: run this box only on the upstream URLs that contain / don't contain <value>. Compiles
# to the engine's ``contains:``/``excludes:`` pipe filter. Value kept to simple chars so it can't break the ref.
_COND_MODES = {"contains", "excludes"}
_COND_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,64}$")


def _parse_when(raw) -> dict | None:
    if not isinstance(raw, dict):
        return None
    value = str(raw.get("value", "") or "").strip()
    if not value:
        return None
    mode = str(raw.get("mode", "contains")).strip().lower()
    if mode not in _COND_MODES:
        raise WorkflowError(f"condition must be one of {sorted(_COND_MODES)}")
    if not _COND_RE.match(value):
        raise WorkflowError("condition value must be 1-64 simple chars (letters, digits, . _ - /)")
    return {"mode": mode, "value": value}


def _parse_conditions(raw) -> list[dict]:
    """Zero or more keep/reject conditions (for a filter box). Each is validated like `when`; ALL must pass
    (they chain as sequential filters = AND). Empty-value conditions are dropped; capped at 8."""
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return []
    out: list[dict] = []
    for item in raw:
        c = _parse_when(item)
        if c:
            out.append(c)
        if len(out) >= 8:
            break
    return out


def _cond_chain(node: dict) -> str:
    """The ``| mode:value`` filter chain for a node: its multi `conditions` (AND) when set, else its single
    `when`, else ''. Chained filters run in sequence, so multiple conditions must all pass."""
    conds = node.get("conditions") or ([node["when"]] if node.get("when") else [])
    return "".join(f" | {c['mode']}:{c['value']}" for c in conds)


def _parse_repeat(raw) -> dict | None:
    """A box's 'repeat until stable' flag -> {max}. The box re-runs on its own growing output until it stops
    finding new items or `max` rounds (clamped 1..10). True is shorthand for the default (3 rounds)."""
    if not raw:
        return None
    if raw is True:
        return {"max": 3}
    if isinstance(raw, dict):
        try:
            m = int(raw.get("max", 3))
        except (TypeError, ValueError):
            m = 3
        return {"max": max(1, min(m, 10))}
    return None


def _limit_count(raw) -> int:
    """A `limit` box's count, read from its args field (a plain integer). Default 100; clamped 1..100000."""
    try:
        n = int(str(raw).strip())
    except (TypeError, ValueError):
        n = 100
    return max(1, min(n, 100000))


def _parse_severities(raw) -> list[str]:
    """The workflow-level findings filter: the severities to KEEP (subset of critical/high/medium/low/info)."""
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return []
    out = [s.strip().lower() for s in raw if isinstance(s, str)]
    bad = [s for s in out if s not in _VALID_SEVERITIES]
    if bad:
        raise WorkflowError(f"unknown severity {bad[0]!r} (use: {', '.join(_VALID_SEVERITIES)})")
    # keep canonical order, de-duped
    return [s for s in _VALID_SEVERITIES if s in set(out)]


class WorkflowError(ValueError):
    """A graph that can't be compiled (bad name, unknown tool, cycle, illegal wiring, ...)."""


def _full_args(node: dict, extra_opt: str = "") -> str:
    """The step's args string: the box's own tool args, plus ``--opt-args '<value>'`` (verbatim passthrough to the
    underlying binary) when the box set an opt-args value or the box is an alias with a preset flag (``extra_opt``,
    e.g. nuclei-dast -> ``-dast``). The value is shlex-quoted so it stays ONE token the tool wrapper forwards to
    the scanner intact. Not applied to flow pseudo-tools (their ``args`` means something else, e.g. limit's N)."""
    args = node.get("args", "") or ""
    opt = (node.get("optargs", "") or "").strip()
    combined = ((extra_opt + " " + opt).strip() if extra_opt else opt)
    if combined and node.get("tool") not in _FLOW_TOOLS:
        args = (args + " --opt-args " + shlex.quote(combined)).strip()
    return args.strip()


def _var(node_id: str) -> str:
    """A collision-safe workflow variable for a node's output. Prefixed so it can never shadow a reserved var
    (``target``/``findings``/``_target``/``_scope``); non-word chars folded to ``_``."""
    return "n_" + re.sub(r"\W+", "_", str(node_id))


def compile_graph(graph: dict, reserved_names: set[str] | None = None,
                  emit_items: list[str] | None = None) -> dict:
    """Compile a node graph to a workflow spec dict. Raises WorkflowError with a human-readable message on any
    invalid graph. ``reserved_names`` (optional) are workflow names already taken (e.g. built-ins) to reject.

    ``emit_items`` (used by :func:`compile_pipeline` for a PRODUCER segment that feeds a fan-out boundary) is a
    list of node ids whose produced URLs/hosts become the workflow's output — so the server records them as scan
    items and fans them out as the next stage's targets, instead of emitting findings. ``None`` keeps the normal
    output (findings when any box makes them, else the last box's list)."""
    if not isinstance(graph, dict):
        raise WorkflowError("graph must be an object")
    name = str(graph.get("name", "")).strip().lower()
    if not _NAME_RE.match(name):
        raise WorkflowError("name must be 2-64 chars, lowercase letters/digits/hyphens, starting alphanumeric")
    if reserved_names and name in reserved_names:
        raise WorkflowError(f"'{name}' is already a workflow name — pick another")

    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    if not isinstance(nodes, list) or not nodes:
        raise WorkflowError("a workflow needs at least one tool box")
    if len(nodes) > _MAX_NODES:
        raise WorkflowError(f"too many boxes (max {_MAX_NODES})")

    by_id: dict[str, dict] = {}
    for n in nodes:
        nid = str(n.get("id", "")).strip()
        tool = str(n.get("tool", "")).strip()
        if not nid:
            raise WorkflowError("every box needs an id")
        if nid in by_id:
            raise WorkflowError(f"duplicate box id '{nid}'")
        if tool not in TOOL_KIND:
            raise WorkflowError(f"unknown tool '{tool}'")
        by_id[nid] = {"id": nid, "tool": tool, "args": str(n.get("args", "") or "").strip(),
                      "optargs": str(n.get("optargs", "") or "").strip(),
                      "kind": TOOL_KIND[tool], "when": _parse_when(n.get("when")),
                      "conditions": _parse_conditions(n.get("conditions")),
                      "repeat": _parse_repeat(n.get("repeat"))}

    incoming: dict[str, list[str]] = {nid: [] for nid in by_id}
    outgoing: dict[str, list[str]] = {nid: [] for nid in by_id}
    for e in edges:
        src, dst = str(e.get("from", "")).strip(), str(e.get("to", "")).strip()
        if src not in by_id or dst not in by_id:
            raise WorkflowError("an edge references an unknown box")
        if src == dst:
            raise WorkflowError("a box can't feed itself")
        if by_id[src]["kind"] == "findings" and by_id[dst]["tool"] not in _FLOW_TOOLS:
            raise WorkflowError(f"'{by_id[src]['tool']}' produces findings — it can only feed a flow box "
                                "(filter / limit), not a scanner that needs a target")
        incoming[dst].append(src)
        outgoing[src].append(dst)

    order = _toposort(by_id, incoming, outgoing)      # raises on a cycle
    has_findings = any(n["kind"] == "findings" for n in by_id.values())

    steps: list[dict] = []
    for nid in order:
        node = by_id[nid]
        parents = incoming[nid]
        start = len(steps)                             # tag every top-level step this box emits with its node id
        if node["tool"] in _FLOW_TOOLS:                # flow nodes: shape the parents' stream (no tool runs).
            # Work on WHATEVER the parents produce - urls, items, or findings:
            #   * findings in  -> filter/limit the shared `findings` set in place (keeps the finding objects);
            #   * urls/items in -> `filter`/`limit` PRESERVE the items (no url coercion), `hosts` collapses to
            #     hostnames, `aggregate` collects + sorts a URL set. A box wired AFTER runs over the result.
            findings_mode = bool(parents) and all(by_id[p]["kind"] == "findings" for p in parents)
            if findings_mode:
                # all parents' findings live in the shared `findings` var; filter/limit it in place. This box is
                # then itself a findings box (feeds only other flow boxes; its result is in the workflow output).
                by_id[nid]["kind"] = "findings"
                sel = "findings" + _cond_chain(node)                  # class/severity/contains/excludes on findings
                if node["tool"] == "limit":
                    sel += " | limit:" + str(_limit_count(node["args"]))
                steps.append({"select": "${" + sel + "}", "set": "findings"})
            else:
                fvar = _var(nid)
                for pid in parents:
                    if node["tool"] == "hosts":
                        proj = _var(pid) + " | urls | hosts"
                    elif node["tool"] == "aggregate":
                        proj = _var(pid) + " | urls" + _cond_chain(node)
                    else:                                 # filter / limit: keep the item kind (urls OR items)
                        proj = _var(pid) + _cond_chain(node)
                    steps.append({"select": "${" + proj + "}", "save": fvar})
                if parents and node["tool"] == "aggregate":
                    steps.append({"select": "${" + fvar + " | sort}", "set": fvar})        # dedup + sort
                elif parents and node["tool"] == "limit":
                    steps.append({"select": "${" + fvar + " | limit:" + str(_limit_count(node["args"])) + "}",
                                  "set": fvar})                                             # cap to N
        else:
            save = "findings" if node["kind"] == "findings" else _var(nid)
            real_tool, alias_opt = _TOOL_ALIAS.get(node["tool"], (node["tool"], ""))
            full_args = _full_args(node, alias_opt)     # tool args + preset (alias) + any --opt-args passthrough
            if not parents:                            # root: runs on the workflow target
                step: dict = {"tool": real_tool, "target": "${target}"}
                if full_args:
                    step["args"] = full_args
                step["save"] = save
                steps.append(step)
            else:                                      # child: run per URL EACH parent produced. With several
                # parents (fan-in), emit one for_each per parent, all saving into the SAME var, so the box runs on
                # the UNION of every upstream's URLs and its output accumulates (save collects across steps).
                for pid in parents:
                    pvar = _var(pid)
                    inner: dict = {"tool": real_tool, "target": "${" + pvar + ".item}"}
                    if full_args:
                        inner["args"] = full_args
                    inner["save"] = save
                    proj = pvar + " | urls" + _cond_chain(node)   # condition(s): grep the piped URLs first
                    steps.append({"for_each": "${" + proj + "}", "do": [inner]})

            # RECURSION: a box flagged 'repeat until stable' re-runs on its OWN growing output after the seed
            # round(s) above, until it finds nothing new or `max` rounds. Only for URL/item producers (a findings
            # box has no list to re-feed). save merges+dedups so it converges; the engine's `repeat` bounds it.
            if node.get("repeat") and node["kind"] != "findings":
                vv = save                              # the box's own output var (_var(nid))
                rinner: dict = {"tool": real_tool, "target": "${" + vv + ".item}"}
                if full_args:
                    rinner["args"] = full_args
                rinner["save"] = vv
                rproj = vv + " | urls" + _cond_chain(node)
                steps.append({"repeat": "${" + vv + " | urls}", "max": node["repeat"]["max"],
                              "do": [{"for_each": "${" + rproj + "}", "do": [rinner]}]})
        for s in steps[start:]:                        # live canvas: map each emitted step back to its box
            s["node"] = nid

    if emit_items:
        # PRODUCER SEGMENT of a fan-out pipeline: emit the union of the boundary producers' URLs/hosts as the
        # workflow output. The server stores these as scan items and promotes them to the NEXT stage's targets,
        # fanning the downstream work out across the whole fleet (one job per item) instead of one long process.
        out_var = "n_segout"
        for pid in emit_items:
            steps.append({"select": "${" + _var(pid) + " | urls}", "save": out_var})
        steps.append({"select": "${" + out_var + " | sort}", "set": out_var})       # de-dup + sort the union
        output = out_var
    else:
        # workflow-level findings filter: keep only the chosen severities before emitting (findings are terminal,
        # so this is a final pass on the collected issues, not a graph node).
        sevs = _parse_severities(graph.get("severities"))
        if sevs and has_findings:
            steps.append({"select": "${findings | severity:" + ",".join(sevs) + "}", "set": "findings"})
        # emit findings when any box produces them; otherwise emit the last box's collected output (a recon-style
        # chain that only enumerates URLs/hosts still returns something listable).
        output = "findings" if has_findings else _var(order[-1])
    spec = {"name": name, "help": str(graph.get("help", "") or f"custom workflow: {name}").strip(),
            "input": "target", "output": output, "steps": steps}
    return spec


def _toposort(by_id, incoming, outgoing) -> list[str]:
    """Kahn's algorithm; raises WorkflowError if the graph has a cycle."""
    indeg = {nid: len(incoming[nid]) for nid in by_id}
    queue = sorted([nid for nid, d in indeg.items() if d == 0])
    order: list[str] = []
    while queue:
        nid = queue.pop(0)
        order.append(nid)
        for m in outgoing[nid]:
            indeg[m] -= 1
            if indeg[m] == 0:
                queue.append(m)
        queue.sort()
    if len(order) != len(by_id):
        raise WorkflowError("the boxes form a loop — connections must flow one way")
    return order


def compile_to_text(graph: dict, reserved_names: set[str] | None = None) -> tuple[dict, str]:
    """Compile and also return the storable workflow-file TEXT (JSON, which the engine parses as YAML)."""
    spec = compile_graph(graph, reserved_names)
    return spec, json.dumps(spec, ensure_ascii=False, indent=2)


def _has_split(edges) -> bool:
    return any(isinstance(e, dict) and e.get("split") for e in (edges or []))


def compile_pipeline(graph: dict, reserved_names: set[str] | None = None) -> list[dict]:
    """Compile a graph into an ORDERED list of workflow SEGMENTS, split at the user's 'fan-out' edges.

    A fan-out edge (``{"from","to","split": true}``) is a boundary where the producer's results should be
    DISTRIBUTED: everything up to it is one segment (stage N), everything after it another (stage N+1) that runs
    on the items stage N produced — one job per item, spread across the whole runner fleet (this is why a
    subfinder → ⦂fan-out⦂ → nuclei graph no longer runs nuclei for every host inside one process on one agent).

    With no split edge this returns a single segment identical to :func:`compile_to_text` (zero behaviour change
    for every existing workflow). With split edges it enforces a single LINEAR chain of stages and returns, in
    order::

        [{"name","spec","yaml","item_filter"}, ...]   # [0] is stage 0 (runs on the scan target)

    ``item_filter`` on segment *i>0* is how the previous stage's items are filtered into this stage's targets
    (``all`` | ``urls``). Raises :class:`WorkflowError` with a human-readable message on any illegal split."""
    if not isinstance(graph, dict):
        raise WorkflowError("graph must be an object")
    name = str(graph.get("name", "")).strip().lower()
    if not _NAME_RE.match(name):
        raise WorkflowError("name must be 2-64 chars, lowercase letters/digits/hyphens, starting alphanumeric")
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    if not isinstance(nodes, list) or not nodes:
        raise WorkflowError("a workflow needs at least one tool box")

    if not _has_split(edges):                     # ordinary single-process workflow — unchanged
        spec, text = compile_to_text(graph, reserved_names)
        node_stage = {str(n.get("id", "")).strip(): 0 for n in nodes if n.get("id")}
        return [{"name": spec["name"], "spec": spec, "yaml": text, "item_filter": "all"}], node_stage

    # ---- index boxes, classify edges (internal vs. the split boundaries) ----
    ids: list[str] = []
    tool_of: dict[str, str] = {}
    node_by_id: dict[str, dict] = {}
    for n in nodes:
        nid = str(n.get("id", "")).strip()
        if not nid:
            raise WorkflowError("every box needs an id")
        if nid in tool_of:
            raise WorkflowError(f"duplicate box id '{nid}'")
        ids.append(nid)
        tool_of[nid] = str(n.get("tool", "")).strip()
        node_by_id[nid] = n

    internal_adj: dict[str, set] = {i: set() for i in ids}
    internal_parents: dict[str, set] = {i: set() for i in ids}
    split_edges: list[tuple[str, str, str]] = []
    for e in edges:
        if not isinstance(e, dict):
            continue
        src, dst = str(e.get("from", "")).strip(), str(e.get("to", "")).strip()
        if src not in tool_of or dst not in tool_of:
            raise WorkflowError("an edge references an unknown box")
        if e.get("split"):
            if TOOL_KIND.get(tool_of[src]) == "findings":
                raise WorkflowError(f"'{tool_of[src]}' produces findings — it can't feed a fan-out boundary "
                                    "(only a box that enumerates hosts/URLs can be split across the fleet)")
            filt = str(e.get("item_filter") or e.get("filter") or "all")
            split_edges.append((src, dst, filt if filt in ("all", "urls") else "all"))
        else:
            internal_adj[src].add(dst)
            internal_adj[dst].add(src)
            internal_parents[dst].add(src)

    # ---- group boxes into segments: connected components over the NON-split edges ----
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a in ids:
        for b in internal_adj[a]:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb
    comp = {i: find(i) for i in ids}
    comps: dict[str, list[str]] = {}
    for i in ids:
        comps.setdefault(comp[i], []).append(i)

    # ---- chain the components via the split edges; require a single linear pipeline ----
    downstream: dict[str, str] = {}
    upstream: dict[str, str] = {}
    boundary_filter: dict[str, str] = {}             # consuming component -> item_filter
    producers: dict[str, set] = {}                   # producing component -> node ids feeding its boundary
    for src, dst, filt in split_edges:
        cs, cd = comp[src], comp[dst]
        if cs == cd:
            raise WorkflowError("a fan-out edge must cross between two groups of boxes, not loop inside one")
        if internal_parents[dst]:
            raise WorkflowError(f"'{tool_of[dst]}' is a fan-out target, so it can't also be wired from a box in "
                                "its own stage — give it only the fan-out input")
        if downstream.get(cs, cd) != cd:
            raise WorkflowError("a stage can only fan out into ONE downstream stage — keep the split a chain")
        if upstream.get(cd, cs) != cs:
            raise WorkflowError("a stage can only receive a fan-out from ONE upstream stage — keep it a chain")
        downstream[cs] = cd
        upstream[cd] = cs
        boundary_filter[cd] = filt
        producers.setdefault(cs, set()).add(src)

    heads = [c for c in comps if c not in upstream]
    if len(heads) != 1:
        raise WorkflowError("the fan-out must be one chain with a single starting stage")
    order_comps: list[str] = []
    seen: set = set()
    c = heads[0]
    while c is not None:
        if c in seen:
            raise WorkflowError("the fan-out stages form a loop — connections must flow one way")
        seen.add(c)
        order_comps.append(c)
        c = downstream.get(c)
    if len(seen) != len(comps):
        raise WorkflowError("every box must be part of the fan-out chain (no disconnected groups)")

    # ---- compile each component into its own workflow segment ----
    reserved = set(reserved_names or ())
    segments: list[dict] = []
    node_stage: dict[str, int] = {}                    # box id -> stage index (for the live canvas)
    for idx, c in enumerate(order_comps):
        for nid in comps[c]:
            node_stage[nid] = idx
        seg_ids = set(comps[c])
        seg_name = name if idx == 0 else f"{name}-s{idx}"
        if seg_name in reserved:
            raise WorkflowError(f"'{seg_name}' is already a workflow name — pick another")
        sub_nodes = [node_by_id[i] for i in ids if i in seg_ids]       # keep the authoring order
        sub_edges = [{"from": str(e.get("from", "")).strip(), "to": str(e.get("to", "")).strip()}
                     for e in edges if isinstance(e, dict) and not e.get("split")
                     and str(e.get("from", "")).strip() in seg_ids and str(e.get("to", "")).strip() in seg_ids]
        is_last = c not in downstream
        emit = sorted(producers.get(c, set())) if not is_last else None
        sub_graph: dict = {"name": seg_name, "nodes": sub_nodes, "edges": sub_edges,
                           "help": str(graph.get("help", "") or "") if idx == 0 else f"{name} — stage {idx}"}
        if is_last:
            sub_graph["severities"] = graph.get("severities")         # findings filter lives on the terminal stage
        spec = compile_graph(sub_graph, reserved_names=None, emit_items=emit)
        segments.append({"name": seg_name, "spec": spec,
                         "yaml": json.dumps(spec, ensure_ascii=False, indent=2),
                         "item_filter": boundary_filter.get(c, "all")})
    return segments, node_stage

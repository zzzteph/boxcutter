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

# tool name -> output kind, mirrored from the engine registry (boxcutter/tools/*.KIND).
#   findings  -> issues; a terminal box (can't feed a downstream box)
#   urls      -> a list of URL/host strings; chains cleanly
#   items/... -> a list (strings, or dicts with a url); chains via the engine's `| urls` projection
TOOL_KIND: dict[str, str] = {
    "api-map": "findings", "blind-oracle": "findings", "bola-walk": "findings",
    "browser-actions": "items", "browser-login": "items", "dirb": "findings", "dirsearch": "findings",
    "dns-brute": "urls", "dnsx": "urls", "fuzz": "findings", "git-extract": "findings",
    "graphql-audit": "findings", "graphql-detect": "urls", "harvest": "items", "http-request": "items",
    "httpx": "items", "js-endpoints": "items", "katana-crawl": "urls", "liveless": "items",
    "mass-assign": "findings",
    "nmap": "endpoints", "nuclei": "findings", "path-bust": "findings", "path-fuzz": "findings",
    "ping-scan": "urls", "scan-secrets": "findings", "screenshot": "screenshots", "smart-enum": "items",
    "sqlmap": "findings", "subfinder": "urls", "swagger-endpoints": "urls", "swagger-parser": "items",
    "swagger-specs": "urls", "vision-verify": "findings", "visual-driver": "items", "wayback": "urls",
    "wayback-domains": "urls", "zap-crawl": "urls", "zap-scan-full": "findings",
    "zap-scan-openapi": "findings", "zap-scan-url": "findings",
    # flow-control pseudo-tools (not real binaries): handled specially by the compiler, not run as a tool.
    "aggregate": "urls", "filter": "urls", "limit": "urls", "hosts": "urls",
}
_FLOW_TOOLS = {"aggregate", "filter", "limit", "hosts"}
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


def _var(node_id: str) -> str:
    """A collision-safe workflow variable for a node's output. Prefixed so it can never shadow a reserved var
    (``target``/``findings``/``_target``/``_scope``); non-word chars folded to ``_``."""
    return "n_" + re.sub(r"\W+", "_", str(node_id))


def compile_graph(graph: dict, reserved_names: set[str] | None = None) -> dict:
    """Compile a node graph to a workflow spec dict. Raises WorkflowError with a human-readable message on any
    invalid graph. ``reserved_names`` (optional) are workflow names already taken (e.g. built-ins) to reject."""
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
                      "kind": TOOL_KIND[tool], "when": _parse_when(n.get("when")),
                      "repeat": _parse_repeat(n.get("repeat"))}

    incoming: dict[str, list[str]] = {nid: [] for nid in by_id}
    outgoing: dict[str, list[str]] = {nid: [] for nid in by_id}
    for e in edges:
        src, dst = str(e.get("from", "")).strip(), str(e.get("to", "")).strip()
        if src not in by_id or dst not in by_id:
            raise WorkflowError("an edge references an unknown box")
        if src == dst:
            raise WorkflowError("a box can't feed itself")
        if by_id[src]["kind"] == "findings":
            raise WorkflowError(f"'{by_id[src]['tool']}' produces findings, not targets — it can't feed a box")
        incoming[dst].append(src)
        outgoing[src].append(dst)

    order = _toposort(by_id, incoming, outgoing)      # raises on a cycle
    has_findings = any(n["kind"] == "findings" for n in by_id.values())

    steps: list[dict] = []
    for nid in order:
        node = by_id[nid]
        parents = incoming[nid]
        if node["tool"] in _FLOW_TOOLS:                # flow nodes: shape parents' URL stream (no tool runs).
            # collect every parent into one var via select+save (merges + dedups); `hosts` collapses URLs to
            # hostnames; then a finalize pass sorts (aggregate) or caps (limit). `filter` keeps/rejects by its
            # condition (contains = keep, excludes = reject). Boxes wired AFTER run over the resulting set.
            fvar = _var(nid)
            base = " | urls | hosts" if node["tool"] == "hosts" else " | urls"
            for pid in parents:
                proj = _var(pid) + base
                if node.get("when"):                   # keep/reject condition (filter; usable on any flow box)
                    proj += f" | {node['when']['mode']}:{node['when']['value']}"
                steps.append({"select": "${" + proj + "}", "save": fvar})
            if parents and node["tool"] == "aggregate":
                steps.append({"select": "${" + fvar + " | sort}", "set": fvar})            # dedup + sort
            elif parents and node["tool"] == "limit":
                steps.append({"select": "${" + fvar + " | limit:" + str(_limit_count(node["args"])) + "}",
                              "set": fvar})                                                 # cap to N
            continue
        save = "findings" if node["kind"] == "findings" else _var(nid)
        if not parents:                                # root: runs on the workflow target
            step: dict = {"tool": node["tool"], "target": "${target}"}
            if node["args"]:
                step["args"] = node["args"]
            step["save"] = save
            steps.append(step)
        else:                                          # child: run per URL EACH parent produced. With several
            # parents (fan-in), emit one for_each per parent, all saving into the SAME var, so the box runs on
            # the UNION of every upstream's URLs and its output accumulates (save collects across steps).
            for pid in parents:
                pvar = _var(pid)
                inner: dict = {"tool": node["tool"], "target": "${" + pvar + ".item}"}
                if node["args"]:
                    inner["args"] = node["args"]
                inner["save"] = save
                proj = pvar + " | urls"
                if node.get("when"):                   # condition: grep the piped URLs before running
                    proj += f" | {node['when']['mode']}:{node['when']['value']}"
                steps.append({"for_each": "${" + proj + "}", "do": [inner]})

        # RECURSION: a box flagged 'repeat until stable' re-runs on its OWN growing output after the seed
        # round(s) above, until it finds nothing new or `max` rounds. Only for URL/item producers (a findings
        # box has no list to re-feed). save merges+dedups so it converges; the engine's `repeat` bounds it.
        if node.get("repeat") and node["kind"] != "findings":
            vv = save                                  # the box's own output var (_var(nid))
            rinner: dict = {"tool": node["tool"], "target": "${" + vv + ".item}"}
            if node["args"]:
                rinner["args"] = node["args"]
            rinner["save"] = vv
            rproj = vv + " | urls"
            if node.get("when"):
                rproj += f" | {node['when']['mode']}:{node['when']['value']}"
            steps.append({"repeat": "${" + vv + " | urls}", "max": node["repeat"]["max"],
                          "do": [{"for_each": "${" + rproj + "}", "do": [rinner]}]})

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

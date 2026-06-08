"""Run workflows defined in YAML.

A YAML workflow is a list of ``steps``. Values flow through named variables
referenced as ``${name | filter | ...}``. A step captures its output with
``save: <var>`` (re-using a var name merges into it). A tool that produces
findings has each finding source-tagged automatically when saved. The top-level
``output: <var>`` declares which variable the workflow returns - conventionally
``findings`` for scan workflows, or a data var like ``hosts`` for recon. A step
with no ``save:`` runs for its side effects and its output is dropped.

To run step(s) per item in a list there is one construct: ``for_each`` with a
nested ``do:`` block (the item becomes each sub-step's target).

Step keys:
  tool:     <tool name>           run a boxcutter tool
  target:   <ref|literal>         what to run on, e.g. ${target} or ${item}
  args:     "<extra cli flags>"   appended to the tool invocation
  save:     <var>                 capture this step's output into <var> (merges)
  pick:     <field[.field]>       extract a field from object output before saving
  select:   <ref>                 save a list produced purely by filtering
  alive:    <ref>                 save the hosts that resolve (dnsx)
  workflow: <name>                run another workflow
  for_each: <ref> + do: [steps]   run nested steps per item; the current item is
                                  ${<list>.item}, e.g. for_each ${live} -> ${live.item}
Top-level ``output: <var>`` names the variable to emit (default: nothing).

Filters (piped with ``|`` inside ``${...}``): see ``filters.FILTERS``.
"""

from __future__ import annotations

import os
import pathlib
import shlex

from ..core.envelope import debug_logger, dedupe, output_result, set_output_kind
from ..tools.registry import BY_NAME
from ._common import call, finding, run_workflow
from .filters import FILTERS


class YamlWorkflow:
    """Adapter that makes a parsed YAML spec look like a workflow module."""

    def __init__(self, spec: dict) -> None:
        self.spec = spec
        self.NAME = spec["name"]
        self.HELP = spec.get("help", f"YAML workflow: {self.NAME}")

    def add_arguments(self, parser) -> None:
        parser.add_argument("target", help=self.spec.get("input", "target"))

    def run(self, args) -> int:
        return run_spec(self.spec, args)


def run_spec(spec: dict, args) -> int:
    dbg = debug_logger(getattr(args, "steps", False) or getattr(args, "debug", False))
    input_name = spec.get("input", "target")
    value = args.target.strip()
    variables: dict[str, object] = {input_name: value, "_target": value}

    for step in spec.get("steps", []):
        _run_step(step, variables, args, dbg)

    # `output:` names the variable to emit (bare name or ${name}). The emitted
    # envelope kind mirrors what the workflow returns.
    out = spec.get("output")
    if out:
        ref = str(out) if str(out).startswith("${") else "${" + str(out) + "}"
        result = _resolve_list(ref, variables)
        if str(out) in ("findings", "report"):
            kind = "findings"
        elif all(isinstance(x, str) for x in result):
            kind = "urls"
        else:
            kind = "items"
    else:
        result, kind = [], "items"
    set_output_kind(kind)
    dbg(f"{len(result)} result(s) [{kind}]")
    output_result(result, args.output)
    return 0


def _run_step(step: dict, variables: dict, args, dbg) -> None:
    if "for_each" in step:
        # Run the nested do: steps once per item. The current item is exposed as
        # ${<list>.item} - named after the list being iterated, so it's clear
        # where it came from and nested loops don't collide.
        var = _loop_var(step["for_each"])
        outer_target = variables.get("_target")
        outer_item = variables.get(var)
        for item in _resolve_list(step["for_each"], variables):
            variables["_target"] = item
            variables[var] = item
            for sub in step.get("do", []):
                _run_step(sub, variables, args, dbg)
        variables["_target"] = outer_target
        variables[var] = outer_item
        return

    if "select" in step:
        _save(step, variables, _resolve_list(step["select"], variables))
        return

    if "alive" in step:
        _run_alive(step, variables, args, dbg)
        return

    if "workflow" in step:
        _run_subworkflow(step, variables, args, dbg)
        return

    if "tool" not in step:
        return

    module = BY_NAME.get(step["tool"])
    if module is None:
        dbg(f"unknown tool '{step['tool']}', skipping")
        return

    extra = shlex.split(str(step.get("args", "")))
    kind = getattr(module, "KIND", "items")  # findings | urls | items
    collected: list = []
    for target in _targets(step, variables):
        dbg(f"{step['tool']} {target}")
        url = target if isinstance(target, str) and target.startswith("http") else None
        for item in call(module, [target, *extra], args):
            if kind == "findings" and isinstance(item, dict):
                collected.append(finding(step["tool"], item, url))  # source-tagged
            else:
                collected.append(item)

    if "save" in step:
        if kind != "findings" and step.get("pick"):
            collected = _pick(collected, step["pick"])
        _save(step, variables, collected)


def _run_alive(step: dict, variables: dict, args, dbg) -> None:
    """Keep the hosts that resolve (dnsx line starts with the host name)."""
    dnsx = BY_NAME.get("dnsx")
    keep: list[str] = []
    for host in _resolve_list(step["alive"], variables):
        dbg(f"dnsx {host}")
        lines = call(dnsx, [host], args) if dnsx else []
        if any(isinstance(line, str) and line.startswith(host) for line in lines):
            keep.append(host)
    _save(step, variables, keep)


def _run_subworkflow(step: dict, variables: dict, args, dbg) -> None:
    from . import WORKFLOWS  # lazy import to avoid a load-time cycle

    sub = {w.NAME: w for w in WORKFLOWS}.get(step["workflow"])
    if sub is None:
        dbg(f"unknown workflow '{step['workflow']}', skipping")
        return

    collected: list = []
    for target in _targets(step, variables):
        dbg(f"workflow {step['workflow']} {target}")
        collected.extend(run_workflow(sub, target, args))  # already source-tagged

    if "save" in step:
        if step.get("pick"):
            collected = _pick(collected, step["pick"])
        _save(step, variables, collected)


def _targets(step: dict, variables: dict) -> list:
    # A step runs on a single value: its `target:`, or - inside a for_each - the
    # current loop item. Iterating a list is always done with for_each/do.
    if "target" in step:
        items = _resolve_list(step["target"], variables)
        return items[:1] if items else [""]
    return [variables["_target"]]


def _loop_var(ref) -> str:
    """Loop-item variable for a for_each ref: ``${live | js}`` -> ``live.item``."""
    base = "loop"
    if isinstance(ref, str) and ref.startswith("${") and ref.endswith("}"):
        base = ref[2:-1].split("|")[0].strip() or "loop"
    return f"{base}.item"


def _resolve_list(ref, variables: dict) -> list:
    """Resolve ``${name | filter | ...}`` (or a literal) to a list."""
    if not (isinstance(ref, str) and ref.startswith("${") and ref.endswith("}")):
        return [ref]
    parts = [p.strip() for p in ref[2:-1].split("|")]
    value = variables.get(parts[0], [])
    items = list(value) if isinstance(value, list) else [value]
    for name in parts[1:]:
        f = FILTERS.get(name)
        if f is not None:
            items = f(items)
    return items


def _pick(items: list, path: str) -> list:
    cur = items
    for key in path.split("."):
        nxt: list = []
        for item in cur:
            if isinstance(item, dict) and key in item:
                value = item[key]
                nxt.extend(value) if isinstance(value, list) else nxt.append(value)
        cur = nxt
    return cur


def _save(step: dict, variables: dict, result: list) -> None:
    name = step["save"]
    combined = list(variables.get(name, [])) + list(result)
    if all(isinstance(x, str) for x in combined):
        combined = dedupe(combined)
    variables[name] = combined


def load_specs() -> list[YamlWorkflow]:
    """Load YAML workflows from the built-in library and an optional user dir
    (env ``BOXCUTTER_WORKFLOWS``). Returns [] if PyYAML isn't installed."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return []

    dirs = [pathlib.Path(__file__).parent / "library"]
    user_dir = os.environ.get("BOXCUTTER_WORKFLOWS")
    if user_dir:
        dirs.append(pathlib.Path(user_dir))

    # Keyed by name so a user spec overrides a built-in of the same name (the
    # user dir is loaded last); new names are simply added.
    by_name: dict[str, YamlWorkflow] = {}
    for directory in dirs:
        if not directory.is_dir():
            continue
        for path in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]):
            try:
                spec = yaml.safe_load(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(spec, dict) and spec.get("name") and isinstance(spec.get("steps"), list):
                by_name[spec["name"]] = YamlWorkflow(spec)
    return list(by_name.values())

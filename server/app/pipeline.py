"""Pipelines: plan building, validation and the data-type filters between stages.

A scan always runs a PLAN - an ordered list of stages. A tool/workflow template is a one-stage plan; a pipeline
template is a DAG of stages. Each stage runs ONE atomic template (tool or engine workflow) per target, as its
own job, so the whole scanner fleet shares the work:

    stage = {"template_id": 7, "from": [-1], "input": "urls", "args": "--timeout 120"}

* ``from``  - where the stage's targets come from: -1 = the scan's own targets, i = what stage i produced.
              Several entries = the union. A stage may only read from EARLIER stages, so a plan is always a DAG.
* ``input`` - which of those items become targets, and in what shape (see INPUTS).
* ``args``  - extra engine flags for this stage only.

A pipeline stage may itself point at another pipeline: it is inlined (its first stages read what this stage
would have read, and anything reading this stage reads that pipeline's final stages). That is how a custom
pipeline can chain two built-in distributed workflows.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
from urllib.parse import parse_qsl, urlsplit

from sqlmodel import Session

from .models import Template

SEED = -1
MAX_STAGES = 200

# input -> label shown in the UI
INPUTS = {
    "all": "Everything",
    "hosts": "Hostnames",
    "urls": "URLs",
    "param-urls": "URLs with parameters",
    "js-urls": "JavaScript files",
    "writes": "POST / PUT / PATCH requests",
}
INPUT_HELP = {
    "all": "every result as-is",
    "hosts": "hostnames only (URLs are reduced to their host)",
    "urls": "http(s) URLs (bare hostnames become https://host)",
    "param-urls": "URLs that carry query parameters, one per path + parameter set",
    "js-urls": "JavaScript file URLs",
    "writes": "captured state-changing requests - the method and body are passed to the tool "
              "(only fuzz and sqlmap understand them)",
}
# a template's `accepts` -> the input a stage feeding it should use by default
DEFAULT_INPUT = {"domain": "hosts", "host": "all", "network": "hosts", "url": "urls", "spec": "urls",
                 "graphql": "urls", "endpoint": "param-urls", "js": "js-urls", "any": "all"}

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$|"
                      r"^\d{1,3}(\.\d{1,3}){3}$", re.I)
_JS_RE = re.compile(r"\.m?js$", re.I)
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class PlanError(ValueError):
    """A pipeline that can't run (unknown template, bad wiring, a loop, ...). The message is user-facing."""


# ---- items -> stage targets ---------------------------------------------------------------------------------
def expand(entry) -> list:
    """Flatten one envelope entry into the raw items it carries. A js-endpoints record nests its endpoint
    objects under ``endpoints``; everything else is a single item (a string or an object)."""
    if isinstance(entry, dict) and isinstance(entry.get("endpoints"), list):
        return [e for e in entry["endpoints"] if isinstance(e, (str, dict))]
    return [entry]


def item_url(it) -> str:
    if isinstance(it, str):
        return it.strip()
    if isinstance(it, dict):
        for k in ("url", "value", "host", "domain", "ip", "endpoint", "item"):
            v = it.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def _is_url(v: str) -> bool:
    return v.lower().startswith(("http://", "https://"))


def _hostname(v: str) -> str:
    if _is_url(v):
        try:
            return (urlsplit(v).hostname or "").lower()
        except ValueError:
            return ""
    v = v.strip().lower().rstrip(".")
    host = v.split("/", 1)[0].split(":", 1)[0]
    return host if _HOST_RE.match(host) else ""


def _k(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:40]


def select_targets(input_name: str, items: list) -> list[tuple[str, str, list]]:
    """Turn a stage's incoming items into ``(value, dedupe_key, extra_argv)`` target triples (de-duplicated
    within the batch; the queue also de-duplicates against what the stage already has)."""
    out: list[tuple[str, str, list]] = []
    seen: set = set()

    def add(value: str, key: str, args: list | None = None):
        if value and len(value) <= 1024 and key not in seen:
            seen.add(key)
            out.append((value, key, args or []))

    for it in items:
        if input_name == "writes":
            if not isinstance(it, dict):
                continue
            method = str(it.get("method", "")).upper()
            url = item_url(it)
            if method not in _WRITE_METHODS or not _is_url(url):
                continue
            body = it.get("body")
            body = body if isinstance(body, str) else (json.dumps(body) if body else "")
            args = ["--method", method] + (["--data", body] if body else [])
            add(url, _k("w", method, url.split("?", 1)[0], body[:500]), args)
            continue
        v = item_url(it)
        if not v:
            continue
        if input_name == "all":
            add(v, _k(v.lower().rstrip("/")))
        elif input_name == "hosts":
            h = _hostname(v)
            if h:
                add(h, _k(h))
        elif input_name == "urls":
            if _is_url(v):
                add(v, _k(v.rstrip("/")))
            else:
                h = _hostname(v)
                if h and h == v.strip().lower().rstrip("."):
                    add("https://" + h, _k("https://" + h))
        elif input_name == "param-urls":
            if not _is_url(v):
                continue
            try:
                p = urlsplit(v)
            except ValueError:
                continue
            names = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
            if names:
                add(v, _k(p.scheme.lower(), p.netloc.lower(), p.path, ",".join(names)))
        elif input_name == "js-urls":
            if not _is_url(v):
                continue
            try:
                path = urlsplit(v).path
            except ValueError:
                continue
            if _JS_RE.search(path):
                add(v, _k(v.lower()))
    return out


# ---- plans --------------------------------------------------------------------------------------------------
def _spec(t: Template) -> dict:
    try:
        return json.loads(t.spec_json or "{}") or {}
    except Exception:  # noqa: BLE001
        return {}


def atomic_stage(t: Template, frm=None, input_name: str = "all", args: str = "", label: str = "") -> dict:
    spec = _spec(t)
    return {"template_id": t.id, "template": t.name, "title": label or t.title or t.name, "kind": t.kind,
            "engine": spec.get("name") or t.name, "params": spec.get("params") or [],
            "produces": t.produces, "accepts": t.accepts, "category": t.category,
            "description": t.description,
            "from": list(frm if frm is not None else [SEED]), "input": input_name, "args": args or ""}


def build_plan(session: Session, template: Template) -> list[dict]:
    """The flattened, validated stage plan for a template. Raises PlanError."""
    if template.kind in ("tool", "workflow"):
        return [atomic_stage(template)]
    if template.kind != "pipeline":
        raise PlanError(f"unknown template kind '{template.kind}'")
    return flatten(session, _spec(template).get("stages") or [], _seen={template.id})


def flatten(session: Session, stages: list, _seen: set | None = None) -> list[dict]:
    """Validate a raw stage list and inline any nested pipeline. Returns the plan (stage dicts, indexed)."""
    if not isinstance(stages, list) or not stages:
        raise PlanError("a workflow needs at least one step")
    seen = set(_seen or ())
    plan: list[dict] = []
    # raw stage index -> the plan indexes that represent its OUTPUT (an atomic stage: itself; an inlined
    # pipeline: its final stages)
    out_of: dict[int, list[int]] = {}
    for i, raw in enumerate(stages):
        if not isinstance(raw, dict):
            raise PlanError(f"step {i + 1} is malformed")
        tid = raw.get("template_id")
        t = session.get(Template, int(tid)) if str(tid or "").isdigit() or isinstance(tid, int) else None
        if t is None:
            raise PlanError(f"step {i + 1}: pick what to run")
        frm_raw = raw.get("from")
        if frm_raw in (None, "", []):
            frm_raw = [SEED] if i == 0 else [i - 1]
        if not isinstance(frm_raw, list):
            frm_raw = [frm_raw]
        frm: list[int] = []
        for f in frm_raw:
            try:
                f = int(f)
            except (TypeError, ValueError):
                raise PlanError(f"step {i + 1}: bad input source")
            if f != SEED and not (0 <= f < i):
                raise PlanError(f"step {i + 1} can only read from the scan targets or an earlier step")
            if f == SEED:
                frm.append(SEED)
            else:
                parent = stages[f]
                ptid = parent.get("template_id") if isinstance(parent, dict) else None
                pt = session.get(Template, int(ptid)) if ptid else None
                if pt is not None and pt.produces == "findings":
                    raise PlanError(f"step {i + 1} reads from step {f + 1} ({pt.title or pt.name}), "
                                    "which only produces findings - nothing to pass on")
                frm.extend(out_of.get(f, []))
        frm = sorted(set(frm))
        input_name = str(raw.get("input") or DEFAULT_INPUT.get(t.accepts, "all"))
        if input_name not in INPUTS:
            raise PlanError(f"step {i + 1}: unknown input '{input_name}'")
        args = str(raw.get("args") or "").strip()
        if args:
            try:
                shlex.split(args)
            except ValueError as e:
                raise PlanError(f"step {i + 1}: extra arguments don't parse ({e})")
        if t.kind == "pipeline":
            if t.id in seen:
                raise PlanError(f"step {i + 1}: '{t.title or t.name}' includes itself")
            sub = flatten(session, _spec(t).get("stages") or [], _seen=seen | {t.id})
            base = len(plan)
            sub_parents = {j for s in sub for j in s["from"] if j != SEED}
            for j, s in enumerate(sub):
                s = dict(s)
                new_from: list[int] = []
                for f in s["from"]:
                    if f == SEED:
                        new_from.extend(frm)          # the nested pipeline's entry reads what this step reads
                    else:
                        new_from.append(base + f)
                s["from"] = sorted(set(new_from))
                if args and j in [k for k in range(len(sub)) if SEED in sub[k]["from"]]:
                    s["args"] = (s["args"] + " " + args).strip()
                plan.append(s)
            out_of[i] = [base + j for j in range(len(sub)) if j not in sub_parents]
        else:
            plan.append(atomic_stage(t, frm, input_name, args, str(raw.get("label") or "").strip()[:80]))
            out_of[i] = [len(plan) - 1]
        if len(plan) > MAX_STAGES:
            raise PlanError(f"too many steps once expanded (max {MAX_STAGES})")
    return plan


def children(plan: list[dict], stage: int) -> list[int]:
    return [i for i, s in enumerate(plan) if stage in s.get("from", [])]


def stage_argv(stage: dict, target: str, target_args: list, vars_: dict) -> list[str]:
    """`boxcutter ...` argv for one job."""
    name = stage.get("engine") or stage.get("template")
    argv = (["workflow", name, target] if stage.get("kind") == "workflow" else [name, target])
    for p in stage.get("params") or []:
        flag = str(p.get("flag") or p.get("key") or "").strip()
        if not flag:
            continue
        argv.append(flag if flag.startswith("-") else "--" + flag)
        if str(p.get("value", "") or "") != "":
            argv.append(str(p["value"]))
    if stage.get("args"):
        argv += shlex.split(stage["args"])
    argv += [str(a) for a in (target_args or [])]
    for p in (vars_.get("custom") or []):
        flag = str(p.get("flag") or p.get("key") or "").strip()
        if not flag:
            continue
        argv.append(flag if flag.startswith("-") else "--" + flag)
        if str(p.get("value", "") or "") != "":
            argv.append(str(p["value"]))
    # make the engine narrate progress to stderr so the live log fills in as the job runs
    extra = ("--steps", "--show-findings", "--debug") if stage.get("kind") == "workflow" else ("--debug",)
    for flag in extra:
        if flag not in argv:
            argv.append(flag)
    return argv

"""Templates (what a scan runs): the built-in catalog, the built-in distributed workflows, and the user's own
pipelines and presets. Built-ins are read-only."""
from __future__ import annotations

import json
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import Scheduler, Template
from ..pipeline import (DEFAULT_INPUT, INPUT_HELP, INPUTS, LEADS, SEED, UNVERIFIED, VERIFIER, PlanError, build_plan,
                        flatten, gives, takes)

router = APIRouter(prefix="/templates", tags=["templates"])

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _spec(t: Template) -> dict:
    try:
        return json.loads(t.spec_json or "{}") or {}
    except Exception:  # noqa: BLE001
        return {}


def _out(t: Template, session: Session | None = None, with_plan: bool = False) -> dict:
    spec = _spec(t)
    engine = spec.get("name") or t.name
    out = {"id": t.id, "name": t.name, "title": t.title or t.name, "kind": t.kind, "builtin": t.builtin,
           "variant_of": t.variant_of, "category": t.category, "accepts": t.accepts, "produces": t.produces,
           "depth": t.depth, "description": t.description, "spec": spec,
           # wiring rules for the builder (the server checks the same in pipeline.check_plan)
           "engine": engine, "takes": sorted(takes(t.accepts, t.kind)), "gives": gives(t.produces),
           "unverified": engine in UNVERIFIED, "verifier": engine == VERIFIER, "leads": engine in LEADS}
    if t.kind == "pipeline":
        out["steps"] = len(spec.get("stages") or [])
    if with_plan and session is not None:
        try:
            out["plan"] = build_plan(session, t)
            out["plan_error"] = ""
        except PlanError as e:
            out["plan"], out["plan_error"] = [], str(e)
    return out


@router.get("")
def list_templates(session: Session = Depends(get_session)):
    rows = session.exec(select(Template).order_by(Template.builtin.desc(), Template.id)).all()
    return [_out(t) for t in rows]


@router.get("/inputs")
def inputs():
    """The data filters a pipeline step can apply to what it reads."""
    return [{"value": k, "label": v, "help": INPUT_HELP[k]} for k, v in INPUTS.items()]


class TemplateIn(BaseModel):
    title: str
    description: str = ""
    kind: str = "pipeline"                 # pipeline | preset (a tool/workflow with fixed extra arguments)
    stages: list[dict] = []                # pipeline: [{template_id, from, input, args}]
    layout: list = []                      # pipeline: [{x, y}] canvas position of each step (the builder)
    base_template_id: int | None = None    # preset: the tool/workflow it wraps
    params: list[dict] = []                # preset: [{flag, value}]


def _slug(session: Session, title: str, exclude_id: int | None = None) -> str:
    base = _SLUG_RE.sub("-", title.lower()).strip("-")[:60] or "custom"
    name, n = base, 2
    while True:
        t = session.exec(select(Template).where(Template.name == name)).first()
        if t is None or t.id == exclude_id:
            return name
        name, n = f"{base}-{n}", n + 1


def _clean_stages(stages: list[dict]) -> list[dict]:
    out = []
    for i, s in enumerate(stages or []):
        frm = s.get("from")
        if frm in (None, ""):
            frm = [SEED] if i == 0 else [i - 1]
        if not isinstance(frm, list):
            frm = [frm]
        out.append({"template_id": s.get("template_id"), "from": frm, "input": s.get("input") or None,
                    "args": str(s.get("args") or "").strip(), "label": str(s.get("label") or "").strip()[:80]})
    return out


def _apply(session: Session, t: Template, body: TemplateIn) -> None:
    title = body.title.strip()
    if not title:
        raise HTTPException(400, "give it a name")
    t.title = title[:200]
    t.description = body.description.strip()
    t.category = "Custom"
    if body.kind == "pipeline":
        stages = _clean_stages(body.stages)
        try:
            plan = flatten(session, stages, _seen={t.id} if t.id else None)
        except PlanError as e:
            raise HTTPException(400, str(e))
        first = session.get(Template, int(stages[0]["template_id"]))
        parents = {f for s in plan for f in s["from"] if f != SEED}
        leaf_kinds = {({"host": "hosts"}.get(s.get("gives"), "urls") if s["kind"] == "merge" else s["produces"])
                      for i, s in enumerate(plan) if i not in parents} - {"findings"}
        t.kind = "pipeline"
        t.accepts = first.accepts if first else "any"
        t.produces = (leaf_kinds.pop() if len(leaf_kinds) == 1 else "items") if leaf_kinds else "findings"
        depths = set(session.exec(select(Template.depth).where(
            Template.id.in_([s["template_id"] for s in plan]))).all())
        t.depth = "deep" if "deep" in depths else ("standard" if "standard" in depths else "quick")
        # store with resolved defaults so the editor shows exactly what runs
        for s in stages:
            st = session.get(Template, int(s["template_id"]))
            s["input"] = s["input"] or DEFAULT_INPUT.get(st.accepts if st else "any", "all")
            s["template_id"] = int(s["template_id"])
            s["from"] = [int(f) for f in s["from"]]
        layout = [{"x": float(p.get("x", 0)), "y": float(p.get("y", 0))} if isinstance(p, dict) else None
                  for p in (body.layout or [])][:len(stages)]
        t.spec_json = json.dumps({"stages": stages, "layout": layout})
    elif body.kind == "preset":
        base = session.get(Template, body.base_template_id or 0)
        if base is None or base.kind not in ("tool", "workflow"):
            raise HTTPException(400, "a preset wraps one tool or workflow")
        params = [{"flag": str(p.get("flag", "")).strip(), "value": str(p.get("value", "") or "")}
                  for p in body.params if str(p.get("flag", "")).strip()]
        t.kind = base.kind
        t.accepts, t.produces, t.depth = base.accepts, base.produces, base.depth
        t.spec_json = json.dumps({"name": _spec(base).get("name") or base.name, "params": params,
                                  "base": base.name})
    else:
        raise HTTPException(400, "kind must be pipeline (a workflow) or preset")


@router.post("")
def create_template(body: TemplateIn, session: Session = Depends(get_session)):
    t = Template(name=_slug(session, body.title), kind="pipeline", builtin=False)
    _apply(session, t, body)
    session.add(t)
    session.commit()
    session.refresh(t)
    return _out(t, session, with_plan=True)


@router.post("/preview")
def preview(body: TemplateIn, session: Session = Depends(get_session)):
    """Validate a pipeline without saving - the editor's live check. Returns the expanded plan or the error."""
    try:
        plan = flatten(session, _clean_stages(body.stages))
    except PlanError as e:
        return {"ok": False, "error": str(e), "plan": []}
    return {"ok": True, "error": "", "plan": plan}


@router.get("/{tid}")
def get_template(tid: int, session: Session = Depends(get_session)):
    t = session.get(Template, tid)
    if not t:
        raise HTTPException(404)
    return _out(t, session, with_plan=True)


@router.put("/{tid}")
def update_template(tid: int, body: TemplateIn, session: Session = Depends(get_session)):
    t = session.get(Template, tid)
    if not t:
        raise HTTPException(404)
    if t.builtin:
        raise HTTPException(400, "built-in templates are read-only — duplicate it to customise")
    _apply(session, t, body)
    t.name = _slug(session, t.title, exclude_id=t.id)
    session.add(t)
    session.commit()
    session.refresh(t)
    return _out(t, session, with_plan=True)


def _users_of(session: Session, tid: int) -> list[str]:
    users = [f"scheduler '{s.name}'" for s in session.exec(select(Scheduler).where(Scheduler.template_id == tid))]
    for p in session.exec(select(Template).where(Template.kind == "pipeline")).all():
        if p.id != tid and any(int(s.get("template_id") or 0) == tid for s in (_spec(p).get("stages") or [])):
            users.append(f"pipeline '{p.title or p.name}'")
    return users


@router.delete("/{tid}")
def delete_template(tid: int, session: Session = Depends(get_session)):
    t = session.get(Template, tid)
    if not t:
        raise HTTPException(404)
    if t.builtin:
        raise HTTPException(400, "built-in templates can't be deleted")
    users = _users_of(session, tid)
    if users:
        raise HTTPException(400, "still used by " + ", ".join(users[:5]))
    session.delete(t)
    session.commit()
    return {"ok": True}

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import Template, User
from ..security import current_user
from ..seed import TOOLS as TOOL_DESC, WORKFLOWS as BUILTIN_WORKFLOWS
from ..workflow_compile import TOOL_KIND, WorkflowError, compile_to_text

router = APIRouter(prefix="/templates", tags=["templates"])

KINDS = {"workflow", "tool", "ai_agent"}


class TemplateIn(BaseModel):
    name: str
    kind: str
    spec: dict = {}                    # {"name": "irvin"|"web-full"|"nuclei", "flags": [...]}
    description: str | None = None
    context: str | None = None
    llm_profile_id: int | None = None


class TemplatePatch(BaseModel):
    name: str | None = None
    kind: str | None = None
    spec: dict | None = None
    description: str | None = None
    context: str | None = None
    llm_profile_id: int | None = None


def _out(t: Template) -> dict:
    return {"id": t.id, "name": t.name, "kind": t.kind, "spec": json.loads(t.spec_json or "{}"),
            "description": t.description, "context": t.context, "llm_profile_id": t.llm_profile_id,
            "owner_id": t.owner_id}


@router.post("")
def create_template(body: TemplateIn, user: User = Depends(current_user),
                    session: Session = Depends(get_session)):
    if body.kind not in KINDS:
        raise HTTPException(400, f"kind must be one of {sorted(KINDS)}")
    t = Template(name=body.name, kind=body.kind, spec_json=json.dumps(body.spec or {}),
                 description=body.description or "",
                 context=body.context, llm_profile_id=body.llm_profile_id, owner_id=user.id)
    session.add(t)
    session.commit()
    session.refresh(t)
    return _out(t)


@router.get("")
def list_templates(user: User = Depends(current_user), session: Session = Depends(get_session)):
    # single shared group: everyone sees every template
    templates = session.exec(select(Template)).all()
    return [_out(t) for t in sorted(templates, key=lambda x: x.id, reverse=True)]


# ---- custom workflow builder: wire tool boxes into a workflow (see docs/workflow-builder-design.md) ----
class WorkflowGraphIn(BaseModel):
    name: str                          # the workflow slug (also the display name); 2-64 [a-z0-9-]
    help: str | None = None
    graph: dict = {}                   # {nodes:[{id, tool, args}], edges:[{from, to}]}
    template_id: int | None = None     # set to UPDATE an existing custom-workflow template


@router.get("/tool-catalog")
def tool_catalog(user: User = Depends(current_user)):
    """The tools a custom workflow can wire together, each with its output KIND so the builder can type its
    ports (findings = terminal, can't feed a downstream box; urls/items = chainable)."""
    return [{"name": n, "kind": k, "terminal": k == "findings", "description": TOOL_DESC.get(n, "")}
            for n, k in sorted(TOOL_KIND.items())]


@router.post("/workflow/preview")
def preview_workflow(body: WorkflowGraphIn, user: User = Depends(current_user)):
    """Compile a graph WITHOUT saving — for the builder's live preview. Returns {spec, yaml} or a 400 with the
    validation message so the UI can show exactly why a wiring is illegal."""
    graph = dict(body.graph or {})
    graph["name"] = body.name or "preview"
    if body.help is not None:
        graph["help"] = body.help
    try:
        spec, text = compile_to_text(graph, reserved_names=set(BUILTIN_WORKFLOWS))
    except WorkflowError as e:
        raise HTTPException(400, str(e))
    return {"spec": spec, "yaml": text}


@router.post("/workflow")
def save_workflow(body: WorkflowGraphIn, user: User = Depends(current_user),
                  session: Session = Depends(get_session)):
    """Compile a node graph into a runnable workflow and persist it as a Template (kind=workflow). The compiled
    spec is stored as JSON text under spec['yaml']; a runner writes it into a BOXCUTTER_WORKFLOWS dir at run time
    so `boxcutter workflow <name>` finds it (see runners.claim + agent.run_job)."""
    graph = dict(body.graph or {})
    graph["name"] = body.name
    if body.help is not None:
        graph["help"] = body.help
    try:
        spec, text = compile_to_text(graph, reserved_names=set(BUILTIN_WORKFLOWS))
    except WorkflowError as e:
        raise HTTPException(400, str(e))
    stored = {"name": spec["name"], "yaml": text, "graph": graph}   # yaml = the workflow file the runner writes
    if body.template_id is not None:
        t = session.get(Template, body.template_id)
        if not t or (t.owner_id != user.id and user.role != "admin"):
            raise HTTPException(403)
        t.name, t.kind, t.spec_json, t.description = body.name, "workflow", json.dumps(stored), spec["help"]
    else:
        t = Template(name=body.name, kind="workflow", spec_json=json.dumps(stored),
                     description=spec["help"], owner_id=user.id)
    session.add(t)
    session.commit()
    session.refresh(t)
    return _out(t)


@router.get("/{tid}")
def get_template(tid: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    t = session.get(Template, tid)
    if not t:
        raise HTTPException(404)
    return _out(t)


@router.patch("/{tid}")
def update_template(tid: int, body: TemplatePatch, user: User = Depends(current_user),
                    session: Session = Depends(get_session)):
    t = session.get(Template, tid)
    if not t or (t.owner_id != user.id and user.role != "admin"):
        raise HTTPException(403)
    if body.kind is not None:
        if body.kind not in KINDS:
            raise HTTPException(400, f"kind must be one of {sorted(KINDS)}")
        t.kind = body.kind
    if body.name is not None:
        t.name = body.name
    if body.spec is not None:
        t.spec_json = json.dumps(body.spec)
    if body.description is not None:
        t.description = body.description
    if body.context is not None:
        t.context = body.context
    if body.llm_profile_id is not None:
        t.llm_profile_id = body.llm_profile_id
    session.add(t)
    session.commit()
    session.refresh(t)
    return _out(t)


@router.delete("/{tid}")
def delete_template(tid: int, user: User = Depends(current_user), session: Session = Depends(get_session)):
    t = session.get(Template, tid)
    if not t or (t.owner_id != user.id and user.role != "admin"):
        raise HTTPException(403)
    session.delete(t)
    session.commit()
    return {"ok": True}

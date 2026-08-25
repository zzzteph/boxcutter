from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import Template, User
from ..security import current_user

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

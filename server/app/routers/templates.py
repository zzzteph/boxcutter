from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import Template, User
from ..security import current_user
from ..seed import TOOLS as TOOL_DESC, WORKFLOWS as BUILTIN_WORKFLOWS
from ..tool_flags import TOOL_FLAGS
from ..workflow_compile import TOOL_KIND, WorkflowError, compile_pipeline

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


# tool -> pipeline stage, so the builder's picker can GROUP the flat tool list (mirrors registry ordering).
_TOOL_GROUP = {
    "subfinder": "Recon", "dnsx": "Recon", "dns-brute": "Recon", "ping-scan": "Recon", "nmap": "Recon",
    "httpx": "Recon", "liveless": "Recon", "api-map": "Recon", "smart-enum": "Recon", "screenshot": "Recon",
    "wayback": "Recon", "wayback-domains": "Recon",
    "katana-crawl": "Crawl", "zap-crawl": "Crawl", "js-endpoints": "Crawl", "js-files": "Crawl",
    "extract-domains": "Crawl", "harvest": "Crawl",
    "browser-login": "Crawl", "browser-actions": "Crawl", "visual-driver": "Crawl", "vision-verify": "Crawl",
    "nuclei": "Vuln scanners", "sqlmap": "Vuln scanners", "blind-oracle": "Vuln scanners",
    "bola-walk": "Vuln scanners", "mass-assign": "Vuln scanners", "dirb": "Vuln scanners",
    "dirsearch": "Vuln scanners", "zap-scan-url": "Vuln scanners", "zap-scan-full": "Vuln scanners",
    "zap-scan-openapi": "Vuln scanners",
    "path-fuzz": "Fuzzing", "path-bust": "Fuzzing", "fuzz": "Fuzzing",
    "scan-secrets": "Secrets", "git-extract": "Secrets",
    "swagger-parser": "API specs", "swagger-endpoints": "API specs", "swagger-specs": "API specs",
    "graphql-detect": "GraphQL", "graphql-audit": "GraphQL",
    "http-request": "Generic",
    "aggregate": "Flow", "filter": "Flow", "limit": "Flow", "hosts": "Flow",
}
_GROUP_ORDER = ["Recon", "Crawl", "Vuln scanners", "Fuzzing", "Secrets", "API specs", "GraphQL",
                "Flow", "Generic", "Other"]
# A short, SPECIFIC noun for what each box actually PRODUCES — because the raw output kind ("items") is the same
# for a dozen tools that emit very different things. Shown on the box as "out: <produces>". Missing -> kind.
_TOOL_PRODUCES = {
    "subfinder": "subdomains", "dnsx": "resolved hosts", "dns-brute": "resolved subdomains",
    "ping-scan": "live hosts", "nmap": "open ports (host:port)", "httpx": "live HTTP services (URLs)",
    "liveless": "live URLs", "api-map": "API findings", "smart-enum": "candidate paths",
    "screenshot": "page screenshots", "wayback": "archived URLs", "wayback-domains": "archived hostnames",
    "katana-crawl": "crawled URLs", "zap-crawl": "crawled URLs", "js-endpoints": "API endpoints",
    "js-files": "JavaScript file URLs", "extract-domains": "referenced hostnames",
    "harvest": "crawled requests (URLs)", "browser-login": "a login session (cookies/token)",
    "browser-actions": "browser action results", "visual-driver": "screenshots + page state",
    "vision-verify": "XSS-confirmation findings",
    "nuclei": "vulnerability findings", "sqlmap": "SQL-injection findings", "blind-oracle": "injection findings",
    "bola-walk": "BOLA/IDOR findings", "mass-assign": "mass-assignment findings",
    "dirb": "discovered paths (findings)", "dirsearch": "discovered paths (findings)",
    "zap-scan-url": "ZAP findings", "zap-scan-full": "ZAP findings", "zap-scan-openapi": "ZAP findings",
    "path-fuzz": "discovered paths (findings)", "path-bust": "discovered paths (findings)",
    "fuzz": "injection findings", "scan-secrets": "exposed-secret findings",
    "git-extract": "extracted source + secrets", "swagger-parser": "API endpoints",
    "swagger-endpoints": "endpoint URLs", "swagger-specs": "OpenAPI spec URLs",
    "graphql-detect": "GraphQL endpoint URLs", "graphql-audit": "GraphQL findings",
    "http-request": "an HTTP response",
    "aggregate": "merged URL set", "filter": "filtered items", "limit": "first N items",
    "hosts": "unique hostnames",
}
# descriptions for synthetic flow pseudo-tools (not in the engine's tool list, so not in TOOL_DESC)
_SYNTH_DESC = {"aggregate": "Collect, de-duplicate and sort everything wired into it into one URL set; the "
                            "boxes after it run once over that union.",
               "filter": "Keep or reject URLs by a text match (set the condition: contains = keep, excludes = "
                         "reject). Boxes after it get only the kept URLs.",
               "limit": "Cap the wired-in URLs to the first N (put N in the box's args field; default 100) - to "
                        "bound cost on a huge recon set.",
               "hosts": "Collapse the wired-in URLs to their unique hostnames."}


@router.get("/tool-catalog")
def tool_catalog(user: User = Depends(current_user)):
    """The tools a custom workflow can wire together, each with its output KIND (findings = terminal, can't feed
    a downstream box; urls/items = chainable) and its pipeline GROUP so the builder's picker can section them."""
    def gkey(name: str):
        g = _TOOL_GROUP.get(name, "Other")
        return (_GROUP_ORDER.index(g), name)
    return [{"name": n, "kind": k, "group": _TOOL_GROUP.get(n, "Other"),
             "terminal": k == "findings", "description": TOOL_DESC.get(n, "") or _SYNTH_DESC.get(n, ""),
             "produces": _TOOL_PRODUCES.get(n, ""),   # specific noun for what this box outputs (vs. the raw kind)
             "flags": TOOL_FLAGS.get(n, [])}      # accepted CLI flags, for live arg validation in the builder
            for n, k in sorted(TOOL_KIND.items(), key=lambda kv: gkey(kv[0]))]


@router.get("/tool-flags")
def tool_flags(user: User = Depends(current_user)):
    """The accepted CLI flags per tool, so New Scan / the template editor can warn about an argument the tool will
    reject (e.g. `-severity` on nuclei) before the scan runs. Tool-native scanner flags go through `--opt-args`."""
    return TOOL_FLAGS


def _preview_text(segments: list[dict]) -> str:
    """Render the compiled segment(s) for the builder's live preview. A single segment shows its YAML as before;
    a fan-out pipeline shows each stage with a header so you can see exactly where the work is distributed."""
    if len(segments) == 1:
        return segments[0]["yaml"]
    parts = []
    for i, s in enumerate(segments):
        head = (f"# ─── stage {i}: {s['name']} — runs on the scan target"
                if i == 0 else
                f"# ─── stage {i}: {s['name']} — fans out across the fleet on stage {i - 1}'s "
                f"{'URLs' if s['item_filter'] == 'urls' else 'items'} (one job each)")
        parts.append(head + "\n" + s["yaml"])
    return "\n\n".join(parts)


@router.post("/workflow/preview")
def preview_workflow(body: WorkflowGraphIn, user: User = Depends(current_user)):
    """Compile a graph WITHOUT saving — for the builder's live preview. Returns {spec, yaml, segments} or a 400
    with the validation message so the UI can show exactly why a wiring is illegal. ``segments`` is the number of
    fan-out stages the graph compiles to (1 = an ordinary single-process workflow)."""
    graph = dict(body.graph or {})
    graph["name"] = body.name or "preview"
    if body.help is not None:
        graph["help"] = body.help
    try:
        segs = compile_pipeline(graph, reserved_names=set(BUILTIN_WORKFLOWS))
    except WorkflowError as e:
        raise HTTPException(400, str(e))
    return {"spec": segs[0]["spec"], "yaml": _preview_text(segs), "segments": len(segs)}


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
        segs = compile_pipeline(graph, reserved_names=set(BUILTIN_WORKFLOWS))
    except WorkflowError as e:
        raise HTTPException(400, str(e))
    seg0 = segs[0]
    spec = seg0["spec"]
    # yaml = the stage-0 workflow file the runner writes; graph = the editable source. A fan-out graph also stores
    # its ordered segments under `pipeline` — the server turns these into real pipeline stages at scan time, so
    # the downstream work fans out across the fleet instead of running inside one process (see scans._builder_stages).
    stored = {"name": spec["name"], "yaml": seg0["yaml"], "graph": graph}
    if len(segs) > 1:
        stored["pipeline"] = [{"name": s["name"], "yaml": s["yaml"], "item_filter": s["item_filter"]} for s in segs]
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

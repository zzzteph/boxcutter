"""Signal-triggered agent skills.

Deep, surface-SPECIFIC methodology (GraphQL, Swagger, ...) does not belong in an agent's always-on base
prompt: on a target that has none of it, it is pure noise. Instead each such playbook lives as a markdown
skill under ``skills/`` and is injected into the system prompt ONLY when its trigger SIGNAL is present in the
run (e.g. graphql-detect found an endpoint). Signals are DETERMINISTIC - derived from what the tools observed,
not from model discretion - so the same target loads the same skills and runs stay reproducible.

Universal plays (token replay, id enumeration, business logic) stay in the base prompt; only surface-gated
playbooks move here. To add one: drop ``<name>.md`` in ``skills/`` and add a row to ``REGISTRY``.
"""
from __future__ import annotations

import os

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")

# signal name -> skill markdown filename. An agent emits a signal when it observes the matching surface.
REGISTRY = {
    "idor": "idor.md",
    "missing-auth": "missing-auth.md",
    "sqli": "sqli.md",
    "rce": "rce.md",
    "injection": "injection.md",
    "nosql": "nosql.md",
    "prototype-pollution": "prototype-pollution.md",
    "deserialization": "deserialization.md",
    "info_disclosure": "info_disclosure.md",
    "secrets": "secrets.md",
    "crypto": "crypto.md",
    "business_logic": "business_logic.md",
    "race_condition": "race_condition.md",
    "privesc": "privesc.md",
    "http_injection": "http_injection.md",
    "graphql": "graphql.md",
    "swagger": "swagger.md",
    "jwt": "jwt.md",
    "xss": "xss.md",
    "ssrf": "ssrf.md",
    "xxe": "xxe.md",
    "file-upload": "file-upload.md",
    "cors": "cors.md",
    "ssti": "ssti.md",
    "open-redirect": "open-redirect.md",
    "lfi": "lfi.md",
    "auth": "auth.md",
}

_CACHE: dict = {}


def _parse(fname: str) -> tuple[dict, str]:
    """Return (frontmatter_meta, body). A skill may open with a `---`-fenced YAML-ish block (name/triggers/
    scope/safety/severity_hint/label); it is stripped from the body so prompts never carry raw frontmatter,
    and exposed as metadata. Files with no frontmatter (the original skills) parse as ({}, whole-file)."""
    if fname in _CACHE:
        return _CACHE[fname]
    meta: dict = {}
    body = ""
    try:
        with open(os.path.join(_DIR, fname), encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        _CACHE[fname] = (meta, body)
        return _CACHE[fname]
    text = raw.lstrip()
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            block = text[3:end].strip()
            body = text[end + 4:].lstrip("\n").strip()
            for line in block.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    meta[k.strip()] = v.strip()
        else:
            body = raw.strip()
    else:
        body = raw.strip()
    _CACHE[fname] = (meta, body)
    return _CACHE[fname]


def _load(fname: str) -> str:
    """The skill BODY (frontmatter stripped), for injection into a prompt."""
    return _parse(fname)[1]


def _desc(fname: str) -> str:
    """The skill's one-line catalog description: frontmatter `label` if present, else its first heading/line."""
    meta, body = _parse(fname)
    if meta.get("label"):
        return meta["label"][:100]
    for ln in body.splitlines():
        s = ln.lstrip("# ").strip()
        if s:
            return s[:100]
    return fname


def catalog() -> list[tuple[str, str]]:
    """(name, one-line description) for every registered skill - shown to an agent that may
    request a skill by name (vera's model-requested load_skill), not just signal-triggered."""
    return [(name, _desc(REGISTRY[name])) for name in sorted(REGISTRY)]


def load(name: str) -> str:
    """The full body of one skill by its registry name, or '' if unknown."""
    fname = REGISTRY.get(name)
    return _load(fname) if fname else ""


def for_signals(signals) -> str:
    """Concatenated bodies of every registered skill whose signal is active, as one prompt block. Returns ""
    when nothing matches, so the base prompt is used unchanged (and appended verbatim otherwise)."""
    bodies = []
    for sig in sorted(set(signals or ())):
        fname = REGISTRY.get(sig)
        if fname:
            body = _load(fname)
            if body:
                bodies.append(body)
    if not bodies:
        return ""
    return ("\n\n# SITUATIONAL PLAYBOOKS (loaded because this scan detected the matching surface - follow the "
            "one(s) that apply)\n\n" + "\n\n---\n\n".join(bodies))

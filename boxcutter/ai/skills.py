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


def _load(fname: str) -> str:
    if fname not in _CACHE:
        try:
            with open(os.path.join(_DIR, fname), encoding="utf-8") as fh:
                _CACHE[fname] = fh.read().strip()
        except OSError:
            _CACHE[fname] = ""
    return _CACHE[fname]


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

"""Artifact harvesting — the safety net that keeps chains alive.

After every tool result we scan the raw output for credentials (JWTs, Bearer tokens, api keys)
even if the model doesn't explicitly report them. The first credential found is promoted to an
identity (label H), so the next agent authenticates with it automatically.
"""

from __future__ import annotations

import re

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_BEARER = re.compile(r"[Bb]earer\s+([A-Za-z0-9._~+/=-]{12,})")
_APIKEY = re.compile(r"(?i)(?:api[_-]?key|x-api-key|access[_-]?token|secret)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9._-]{16,})")


def harvest(ctx, text: str, source: str = "") -> list:
    """Pull credentials out of a tool result into ctx.secrets; promote a JWT to identity 'H'."""
    if not text:
        return []
    found = []
    seen = {s.get("value") for s in ctx.secrets}

    for tok in _JWT.findall(text):
        if tok not in seen:
            ctx.secrets.append({"kind": "jwt", "value": tok, "source": source})
            seen.add(tok)
            found.append(("jwt", tok))
    for tok in _BEARER.findall(text):
        if tok not in seen and not tok.lower().startswith("ey"):  # avoid double-counting a JWT
            ctx.secrets.append({"kind": "bearer", "value": tok, "source": source})
            seen.add(tok)
            found.append(("bearer", tok))
    for tok in _APIKEY.findall(text):
        if tok not in seen:
            ctx.secrets.append({"kind": "apikey", "value": tok, "source": source})
            seen.add(tok)
            found.append(("apikey", tok))

    # promote the first usable bearer/JWT to a shared identity if we don't have a harvested one yet
    if not any(k == "H" for k in ctx.identities):
        for kind, val in found:
            if kind in ("jwt", "bearer"):
                ctx.add_identity("H", ["--header", f"Authorization: Bearer {val}"], source or "scan")
                break
    return found

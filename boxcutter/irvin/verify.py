"""Deterministic verification gate - plain code, so the LLM cannot fake it.

`reproduce()` independently re-issues a candidate finding's request and checks that the claimed evidence
actually appears in a FRESH response. It only attests classes a single request can prove (reflected XSS,
exposure, secret, LFI, SSTI, error-based SQLi, open-redirect, CORS). Classes that need multi-step proof
(BOLA across identities, blind SQLi/RCE) return False here and are escalated to each executor's independent
re-test agent. Evidence that is redacted simply won't match - that also escalates, never auto-passes.

Endpoint EXISTENCE (is a discovered path real, or just a catch-all/soft-404 fallback?) is NOT decided here -
each path-guessing executor re-verifies its own paths AGENTICALLY (see Executor.verify_endpoints), because a
200 is not proof on a `try_files`/SPA/200-on-miss host.
"""

from __future__ import annotations

import json
import re

# classes whose evidence typically shows up verbatim in one response body
_SINGLE_SHOT = {"xss", "exposure", "secret", "lfi", "ssti", "error", "open-redirect", "cors", "rce", "idor"}


def _strongest_identity(ctx) -> list:
    ids = ctx.landscape.get("identities") or {}
    return list(ids[max(ids)]) if ids else []


def _response_text(out: str) -> str:
    """Pull the searchable text (body/title/status/headers) out of an http-request envelope."""
    try:
        env = json.loads(out)
    except Exception:  # noqa: BLE001
        return out or ""
    data = env.get("data")
    if isinstance(data, list) and data and isinstance(data[0], dict):
        d = data[0]
        return " ".join(str(d.get(k, "")) for k in ("status", "url", "title", "headers", "content"))
    return out or ""


def reproduce(ctx, finding: dict, runner) -> bool:
    """True only if a fresh request independently reproduces the finding's evidence."""
    url = (finding.get("url") or "").strip()
    cls = (finding.get("cls") or "").lower()
    ev = (finding.get("evidence") or "").strip()
    if not url.startswith(("http://", "https://")) or cls not in _SINGLE_SHOT:
        return False
    # normalise the evidence: drop redaction markers and collapse whitespace
    chunk = re.sub(r"\s+", " ", ev).replace("***", "").replace("[REDACTED]", "").replace("…", "").strip()
    if len(chunk) < 6:
        return False
    out = runner(["http-request", url] + _strongest_identity(ctx), ctx=ctx, allowed={"http-request"})
    return chunk[:60] in _response_text(out)

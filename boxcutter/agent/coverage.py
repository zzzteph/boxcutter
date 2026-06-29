"""Deterministic coverage sweep - the routine manual checks run in CODE, not left to the model.

Doctrine (from the user): the model keeps its flexibility for the creative tricks, but the must-always-
happen manual checks have to be deterministic and exhaustive. This sweep walks EVERY endpoint on the
shared surface (the documented spec + everything discovered) and fires the standard injection battery
through `fuzz` - which self-confirms sqli/xss/ssti/lfi/ssrf/xxe/nosql/error - and ingests the findings
straight into ctx. A lazy or weak model can then no longer skip the obvious bugs: the nomnom run missed
sqli (/dishes/search), ssrf (/tools/fetch), xxe (/orders/import) and ssti (/notify/preview) precisely
because those routine checks were left to model discretion. The orchestrator runs this after recon/api
have populated the surface; the resulting findings flow through flows.expand() -> validator like any other.
"""

from __future__ import annotations

import json
import re
import sys

from .context import Finding

# fuzz tags the vuln class in its finding title, e.g. "[GET] [sqli] in 'q' (...)"
_VULN_CLS = {"sqli", "xss", "ssti", "lfi", "rce", "xxe", "nosql", "error", "numeric"}
_CLS_CANON = {"error-disclosure": "error", "numeric": "bola"}
_BRACKET = re.compile(r"\[([a-z\-]+)\]")
_HAS_ID = re.compile(r"/\d+(?:/|$)")


def _canon_url(url: str) -> str:
    """Drop fuzz markers so one fuzz call tests ALL params/path-ids of an endpoint (and so the per-param
    {FUZZ} variants of one endpoint collapse to a single canonical URL)."""
    return url.replace("{FUZZ}", "1").replace("{NUMBERS}", "1")


def _endpoints(ctx) -> list:
    seen: list[str] = []
    s = ctx.surface
    for k in ("param_urls", "endpoints", "tier1", "paths"):
        for u in s.get(k, []):
            if isinstance(u, str) and u.startswith(("http://", "https://")):
                cu = _canon_url(u)
                if cu not in seen:
                    seen.append(cu)
    return seen


def _identity(ctx) -> list:
    """The strongest identity's header tokens (prefer a harvested H* over provided A/B), so authed-only
    endpoints are reachable during the sweep."""
    if not ctx.identities:
        return []
    return list(ctx.identities.get(max(ctx.identities), []))


def _cls_of(title: str) -> str:
    for tok in _BRACKET.findall(title or ""):
        if tok in _VULN_CLS:
            return _CLS_CANON.get(tok, tok)
    return ""


def _ingest(ctx, out) -> int:
    try:
        env = json.loads(out)
    except Exception:  # noqa: BLE001
        return 0
    if not env.get("success") or env.get("kind") != "findings":
        return 0
    n = 0
    for d in env.get("data") or []:
        if not isinstance(d, dict):
            continue
        title = d.get("title", "")
        url = d.get("url", "")
        ctx.add(Finding("coverage", str(d.get("severity", "info")).title(), title, url,
                        _cls_of(title), d.get("info", ""), str(d.get("evidence", ""))[:100],
                        d.get("reproduce") or ["fuzz", url]))
        n += 1
    return n


def sweep(runner, ctx, cap: int = 40) -> None:
    """Fuzz every surface endpoint (deterministic injection coverage); ingest findings into ctx."""
    eps = _endpoints(ctx)
    if not eps:
        return
    # injectable first: a query string or an id-like path segment is the likeliest sink
    eps.sort(key=lambda u: 0 if ("?" in u or _HAS_ID.search(u)) else 1)
    eps = eps[:cap]
    ident = _identity(ctx)
    ctx.current_agent = "coverage"
    sys.stderr.write(f"[coverage] deterministic sweep: fuzzing {len(eps)} endpoint(s) "
                     f"(identity={'yes' if ident else 'none'})\n")
    added = 0
    for url in eps:
        ctx.plan_add(f"fuzz {url}", "surface endpoint (spec/discovered) - deterministic injection check",
                     by="coverage")
        try:
            out = runner(["fuzz", url, *ident], allowed={"fuzz"}, ctx=ctx)
        except Exception as exc:  # noqa: BLE001 - one endpoint blowing up must not abort the sweep
            ctx.note(f"coverage: fuzz failed on {url}: {exc}")
            continue
        added += _ingest(ctx, out)
    sys.stderr.write(f"[coverage] sweep complete: {added} candidate finding(s) from {len(eps)} endpoint(s)\n")
    ctx.note(f"coverage sweep: fuzzed {len(eps)} endpoint(s) -> {added} candidate finding(s)")

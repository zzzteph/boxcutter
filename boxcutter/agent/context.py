"""Shared engagement state — the bus that makes agents clever across the pipeline.

Every agent reads the Context (surface, identities incl. *harvested* tokens, prior findings,
handoffs) and writes back to it. A JWT an early agent pulls from a test endpoint lands in
`identities`, so later agents authenticate with it automatically — that's how chains propagate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_SURFACE = ("live", "param_urls", "js", "paths", "api", "graphql", "spec", "endpoints", "tier1")


@dataclass
class Finding:
    agent: str
    severity: str = "info"          # High | Medium | Low | info
    title: str = ""
    url: str = ""
    cls: str = ""                   # sqli | xss | bola | exposure | secret | ...
    info: str = ""
    evidence: str = ""
    reproduce: list = field(default_factory=list)   # boxcutter argv that reproduces it
    confirmed: bool = False

    def key(self):
        return (self.title.strip().lower(), self.url)


@dataclass
class Context:
    target: str
    mode: str = "fast"
    base_url: str = ""
    identities: dict = field(default_factory=dict)   # label -> ["--header", "..."]
    secrets: list = field(default_factory=list)       # harvested {kind, value, source}
    surface: dict = field(default_factory=lambda: {k: [] for k in _SURFACE})
    stack: str = ""
    nuclei_tags: str = "exposure,misconfig,cve,kev,panel"
    app_profile: dict = field(default_factory=dict)    # what the app IS: purpose/domain/roles/objects/actions
    aggressive: bool = False                            # allow state-mutating methods (PUT/PATCH/DELETE)
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)          # coverage notes
    handoffs: dict = field(default_factory=dict)       # agent -> short summary

    # -- writes -----------------------------------------------------------
    def add(self, f: Finding) -> Finding:
        for g in self.findings:
            if g.key() == f.key():
                return g
        self.findings.append(f)
        return f

    def note(self, msg: str):
        if msg and msg not in self.notes:
            self.notes.append(msg)

    def add_identity(self, label: str, headers: list, source: str = ""):
        self.identities[label] = headers
        if source:
            self.note(f"identity '{label}' harvested from {source}")

    def add_surface(self, key: str, items):
        bucket = self.surface.setdefault(key, [])
        for it in items:
            if it and it not in bucket:
                bucket.append(it)

    # -- reads (for prompts) ---------------------------------------------
    def identities_block(self) -> str:
        if not self.identities:
            return "(none - unauthenticated)"
        return "; ".join(f"{k}=[{' '.join(v)}]" for k, v in self.identities.items())

    def brief(self) -> str:
        s = self.surface
        out = [
            f"TARGET={self.target}  BASE={self.base_url or '?'}  STACK={self.stack or '?'}  MODE={self.mode}",
            f"IDENTITIES (use the strongest on every call): {self.identities_block()}",
            "SURFACE: " + " ".join(f"{k}={len(s.get(k, []))}" for k in _SURFACE),
            "RULES: " + ("AGGRESSIVE - state-mutating methods (PUT/PATCH/DELETE) permitted on this authorized target"
                         if self.aggressive else
                         "safe - prove impact non-destructively; no PUT/PATCH/DELETE"),
        ]
        if self.app_profile:
            p = self.app_profile
            out.append(f"APP PROFILE: {p.get('purpose', '?')}  [domain={p.get('domain', '?')} "
                       f"target_type={p.get('target_type', '?')} risk={p.get('risk', '?')}]")
            for k in ("roles", "key_objects", "sensitive_actions", "trust_boundaries"):
                if p.get(k):
                    out.append(f"  {k.replace('_', ' ')}: " + ", ".join(str(x) for x in p[k]))
        if self.secrets:
            out.append("HARVESTED: " + "; ".join(f"{x.get('kind')}@{x.get('source')}" for x in self.secrets[:8]))
        if self.handoffs:
            out.append("PRIOR HANDOFFS:\n" + "\n".join(f"  [{k}] {v}" for k, v in self.handoffs.items()))
        sample = (s["tier1"] or s["param_urls"] or s["endpoints"] or s["paths"])[:25]
        if sample:
            out.append("URLS TO ACT ON:\n" + "\n".join("  " + u for u in sample))
        return "\n".join(out)

    def findings_dump(self) -> str:
        if not self.findings:
            return "(no candidate findings)"
        return "\n".join(
            f"  [{f.severity}|{'confirmed' if f.confirmed else 'candidate'}] {f.title} @ {f.url} "
            f":: repro={' '.join(f.reproduce) or '-'}"
            for f in self.findings)

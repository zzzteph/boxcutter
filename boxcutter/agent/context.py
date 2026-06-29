"""Shared engagement state — the bus that makes agents clever across the pipeline.

Every agent reads the Context (surface, identities incl. *harvested* tokens, prior findings,
handoffs) and writes back to it. A JWT an early agent pulls from a test endpoint lands in
`identities`, so later agents authenticate with it automatically — that's how chains propagate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_SURFACE = ("live", "param_urls", "js", "paths", "api", "graphql", "spec", "endpoints", "tier1")
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(severity: str) -> int:
    return _SEV_ORDER.get(str(severity).strip().lower(), 0)


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
    status: str = "candidate"                        # candidate | confirmed | downgraded | dropped

    def key(self):
        return (self.title.strip().lower(), self.url)


@dataclass
class Session:
    """A self-managed login: bob obtains access+refresh, then refreshes/re-logins on expiry."""
    label: str
    creds: tuple = ()            # (user, pass)
    login_url: str = ""
    refresh_url: str = ""
    kind: str = "bearer"        # bearer | cookie
    access: str = ""
    refresh: str = ""
    header_name: str = "Authorization"
    alive: bool = False

    def auth_header(self):
        if not self.access:
            return None
        return f"Cookie: {self.access}" if self.kind == "cookie" else f"{self.header_name}: Bearer {self.access}"


@dataclass
class Context:
    target: str
    mode: str = "fast"
    base_url: str = ""
    identities: dict = field(default_factory=dict)   # label -> ["--header", "..."]  (render/use source)
    sessions: dict = field(default_factory=dict)      # label -> Session (self-managed login lifecycle)
    active_label: str = "A"
    secrets: list = field(default_factory=list)       # harvested {kind, value, source}
    surface: dict = field(default_factory=lambda: {k: [] for k in _SURFACE})
    stack: str = ""
    nuclei_tags: str = "exposure,misconfig,cve,kev,panel"
    app_profile: dict = field(default_factory=dict)    # what the app IS: purpose/domain/roles/objects/actions
    aggressive: bool = False                            # allow state-mutating methods (PUT/PATCH/DELETE)
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)          # coverage notes
    follow_ups: list = field(default_factory=list)     # explicit finding-derived next-step directives (flows.py)
    plan: list = field(default_factory=list)            # explicit ordered worklist: what orca did/queued + WHY
    handoffs: dict = field(default_factory=dict)       # agent -> short summary
    ledger: list = field(default_factory=list)          # every tool call - deterministic ground truth
    responses: dict = field(default_factory=dict)       # argv -> captured output (for evidence checks)
    skipped: list = field(default_factory=list)          # agents the coordinator skipped
    stop_reasons: dict = field(default_factory=dict)     # agent -> done | capped | stalled | error
    current_agent: str = ""
    low_coverage: bool = False
    coverage_reason: str = ""
    baseline: str = ""          # captured base-page response, to filter boilerplate "evidence"
    entry: str = "domain"        # domain | url | endpoint - controls recon breadth + scope

    # -- writes -----------------------------------------------------------
    def add(self, f: Finding) -> Finding:
        for g in self.findings:
            # same (title,url), or the same vuln class on the same url phrased differently
            if g.key() == f.key() or (f.cls and g.cls == f.cls and g.url == f.url):
                if _sev_rank(f.severity) > _sev_rank(g.severity):
                    g.severity = f.severity
                if len(f.evidence) > len(g.evidence):
                    g.evidence = f.evidence
                if f.status == "confirmed":
                    g.status = "confirmed"
                return g
        self.findings.append(f)
        return f

    def note(self, msg: str):
        if msg and msg not in self.notes:
            self.notes.append(msg)

    def add_follow_up(self, cls: str, url: str, steps, agents=(), src: str = ""):
        """Stage an explicit, finding-derived next-step directive (deduped by class+url). flows.py fills these;
        an agent reads the ones addressed to it via follow_ups_block()."""
        for e in self.follow_ups:
            if e["cls"] == cls and e["url"] == url:
                return
        self.follow_ups.append({"cls": cls, "url": url, "steps": list(steps),
                                "agents": list(agents), "src": src})
        self.plan_add(f"follow-up: {cls.upper()} @ {url}", f"chained from {src or cls}",
                      by="flows", status="queued")

    def plan_add(self, action: str, reason: str = "", by: str = "", status: str = "done"):
        """Append one explicit step to the execution plan - the auditable record of WHAT was done/queued and
        WHY. Deterministic tool steps (coverage fuzz, follow-ups) cost no LLM tokens; only `agent:` steps do,
        which is what makes the plan a basis for cost estimation."""
        self.plan.append({"n": len(self.plan) + 1, "action": action, "reason": reason,
                          "by": by or self.current_agent, "status": status})

    def plan_render(self, limit: int = 200) -> str:
        if not self.plan:
            return ""
        out = ["=== EXECUTION PLAN (ordered - WHAT was done/queued and WHY) ==="]
        for e in self.plan[:limit]:
            line = f"{e['n']:>3}. [{e['status']}] {e['action']}"
            if e.get("reason"):
                line += f"  <- {e['reason']}"
            if e.get("by"):
                line += f"  ({e['by']})"
            out.append(line)
        if len(self.plan) > limit:
            out.append(f"     ...(+{len(self.plan) - limit} more steps)")
        return "\n".join(out)

    def follow_ups_block(self, agent: str, limit: int = 10) -> str:
        rel = [e for e in self.follow_ups if not e["agents"] or agent in e["agents"]]
        if not rel:
            return ""
        out = ["EXPLICIT FOLLOW-UPS (chained from what earlier agents already FOUND - these are REQUIRED next "
               "steps for you, bound to the real URL; do them before exploring elsewhere):"]
        for e in rel[:limit]:
            out.append(f"- {e['cls'].upper()} @ {e['url']}:")
            for i, s in enumerate(e["steps"], 1):
                out.append(f"    {i}. {s}")
        return "\n".join(out)

    def add_identity(self, label: str, headers: list, source: str = ""):
        self.identities[label] = headers
        if source:
            self.note(f"identity '{label}' harvested from {source}")

    def sync_identity(self, sess: Session):
        """Mirror a managed session's current token into identities (the render/use source)."""
        header = sess.auth_header()
        if header:
            self.identities[sess.label] = ["--header", header]

    def active_session(self):
        s = self.sessions.get(self.active_label)
        if s and s.access:
            return s
        return next((s for s in self.sessions.values() if s.access), None)

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
            f"TARGET={self.target}  BASE={self.base_url or '?'}  STACK={self.stack or '?'}  "
            f"MODE={self.mode}  ENTRY={self.entry}",
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

    def findings_dump(self, limit: int = 80) -> str:
        if not self.findings:
            return "(no candidate findings)"
        # show live findings first, highest severity first; cap so context can't blow up
        items = sorted(self.findings, key=lambda f: (f.status == "dropped", -_sev_rank(f.severity)))
        lines = [
            f"  [{f.severity}|{f.status}] {f.title} @ {f.url} :: repro={' '.join(f.reproduce) or '-'}"
            for f in items[:limit]
        ]
        if len(items) > limit:
            lines.append(f"  ...(+{len(items) - limit} more omitted to bound context)")
        return "\n".join(lines)

    # -- honesty: deterministic ground truth -----------------------------
    def record(self, tool, target, ok, kind, n, status=None, cached=False):
        self.ledger.append({"agent": self.current_agent, "tool": tool, "target": target,
                            "ok": ok, "kind": kind, "n": n, "status": status, "cached": cached})

    def evidence_seen(self, text) -> bool:
        """True if this concrete evidence string actually appears in some captured tool response.
        Redacted/elided evidence can't be verified, so it is not penalised."""
        t = (text or "").strip().lower()
        if len(t) < 6 or "<redacted>" in t or "..." in t:
            return True
        return any(t in (r or "").lower() for r in self.responses.values())

    def in_baseline(self, text) -> bool:
        """True if the 'evidence' is just boilerplate present on the base page (likely a false positive)."""
        t = (text or "").strip().lower()
        return bool(self.baseline) and len(t) >= 6 and t in self.baseline.lower()

    def coverage_report(self) -> str:
        """A machine-generated facts block built from the tool ledger - the model cannot fake it."""
        counts = {}
        for e in self.ledger:
            counts[e["tool"]] = counts.get(e["tool"], 0) + 1
        sev = {}
        for f in self.findings:
            sev[f.status] = sev.get(f.status, 0) + 1
        s = self.surface
        out = ["=== VERIFIED RUN FACTS (machine-generated from the tool ledger, not the model) ==="]
        out.append("tool calls: " + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
                   + f"  ({len(self.ledger)} total)")
        out.append(f"surface: params {len(s['param_urls'])} | endpoints {len(s['endpoints'])} | "
                   f"js {len(s['js'])} | paths {len(s['paths'])}")
        ids = sorted(set(self.sessions) | set(self.identities))
        out.append("identities: " + (", ".join(ids) if ids else "none (unauthenticated)"))
        out.append("findings by status: " + (", ".join(f"{k} {v}" for k, v in sorted(sev.items())) or "none"))
        if self.skipped:
            out.append("agents skipped (trigger not met / tool unavailable): " + ", ".join(self.skipped))
        partial = [f"{a}:{r}" for a, r in self.stop_reasons.items() if r != "done"]
        if partial:
            out.append("agents stopped early (partial coverage): " + ", ".join(partial))
        if self.low_coverage:
            out.append("LOW COVERAGE: " + (self.coverage_reason or "results likely incomplete"))
        plan = self.plan_render()
        if plan:
            out.append("")
            out.append(plan)
        return "\n".join(out)

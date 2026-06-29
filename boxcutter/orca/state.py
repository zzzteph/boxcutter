"""orca state - the blackboard every layer reads/writes, plus the dynamic work-queue and the plan ledger.

The planner pops the next Task, an executor runs it and writes findings/surface/identities back, advisors
read the whole thing to emit Suggestions, and the planner appends new Tasks. `plan` is the ordered,
reasoned record of WHAT ran and WHY (the audit trail + the basis for token estimation: only planner and
LLM-executor steps cost tokens). Standalone - no bob imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_SURFACE = ("live", "param_urls", "js", "paths", "api", "graphql", "spec", "endpoints", "tier1")
_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CLS_BRACKET = re.compile(r"\[([a-z\-]+)\]")
_VULN_CLS = {"sqli", "xss", "ssti", "lfi", "rce", "xxe", "nosql", "error", "numeric"}


def sev_rank(s: str) -> int:
    return _SEV.get(str(s).strip().lower(), 0)


@dataclass
class Task:
    action: str                       # executor name to run
    args: dict = field(default_factory=dict)
    reason: str = ""
    by: str = "orca"                  # who scheduled it (orca / an advisor name / seed)
    status: str = "queued"            # queued | running | done | failed
    id: int = 0
    result: str = ""

    def sig(self):
        return (self.action, tuple(sorted((k, str(v)) for k, v in self.args.items())))


@dataclass
class Suggestion:
    action: str
    args: dict = field(default_factory=dict)
    reason: str = ""
    priority: int = 5                 # 1 = highest
    by: str = "advisor"


@dataclass
class Finding:
    severity: str = "info"
    title: str = ""
    url: str = ""
    cls: str = ""
    evidence: str = ""
    info: str = ""
    status: str = "candidate"
    by: str = ""

    def key(self):
        return (self.title.strip().lower(), self.url)


@dataclass
class State:
    target: str
    base_url: str = ""
    aggressive: bool = True
    identities: dict = field(default_factory=dict)     # label -> ["--header", "..."]
    secrets: list = field(default_factory=list)        # {kind, value, source}
    surface: dict = field(default_factory=lambda: {k: [] for k in _SURFACE})
    findings: list = field(default_factory=list)
    queue: list = field(default_factory=list)          # list[Task] (FIFO; planner appends to the bottom)
    plan: list = field(default_factory=list)           # ordered audit trail
    notes: list = field(default_factory=list)
    responses: dict = field(default_factory=dict)      # argv-tuple -> output (evidence)
    ledger: list = field(default_factory=list)         # every tool call
    seen_tasks: set = field(default_factory=set)       # task signatures already queued/run (dedupe)
    _next_id: int = 0

    # -- queue ----------------------------------------------------------------
    def enqueue(self, task: Task, dedupe: bool = True) -> bool:
        if dedupe and task.sig() in self.seen_tasks:
            return False
        self.seen_tasks.add(task.sig())
        self._next_id += 1
        task.id = self._next_id
        self.queue.append(task)
        self.plan_add(f"queue {task.action} {self._args_str(task.args)}", task.reason,
                      by=task.by, status="queued")
        return True

    def pop(self):
        return self.queue.pop(0) if self.queue else None

    # -- writes ---------------------------------------------------------------
    def add_finding(self, f: Finding) -> Finding:
        for g in self.findings:
            if g.key() == f.key() or (f.cls and g.cls == f.cls and g.url == f.url):
                if sev_rank(f.severity) > sev_rank(g.severity):
                    g.severity = f.severity
                if len(f.evidence) > len(g.evidence):
                    g.evidence = f.evidence
                if f.status == "confirmed":
                    g.status = "confirmed"
                return g
        self.findings.append(f)
        return f

    def add_surface(self, key: str, items):
        bucket = self.surface.setdefault(key, [])
        for it in items:
            if it and it not in bucket:
                bucket.append(it)

    def add_urls(self, urls):
        """Classify discovered URLs into the surface (param URLs vs plain endpoints)."""
        for u in urls:
            if isinstance(u, str) and u.startswith(("http://", "https://")):
                self.add_surface("param_urls" if "?" in u else "endpoints", [u])

    def add_identity(self, label: str, headers: list, source: str = ""):
        self.identities[label] = headers
        if source:
            self.note(f"identity '{label}' from {source}")

    def add_secret(self, kind, value, source=""):
        if value and value not in {s.get("value") for s in self.secrets}:
            self.secrets.append({"kind": kind, "value": value, "source": source})

    def note(self, msg: str):
        if msg and msg not in self.notes:
            self.notes.append(msg)

    def record(self, argv, out):
        self.responses[tuple(argv)] = out
        self.ledger.append({"tool": argv[0], "target": argv[1] if len(argv) > 1 else ""})

    # -- plan / audit ---------------------------------------------------------
    def plan_add(self, action: str, reason: str = "", by: str = "orca", status: str = "done"):
        self.plan.append({"n": len(self.plan) + 1, "action": action, "reason": reason,
                          "by": by, "status": status})

    def plan_render(self, limit: int = 250) -> str:
        if not self.plan:
            return ""
        out = ["=== ORCA EXECUTION PLAN (ordered - WHAT ran/queued and WHY) ==="]
        for e in self.plan[:limit]:
            line = f"{e['n']:>3}. [{e['status']}] {e['action']}"
            if e.get("reason"):
                line += f"  <- {e['reason']}"
            if e.get("by"):
                line += f"  ({e['by']})"
            out.append(line)
        if len(self.plan) > limit:
            out.append(f"     ...(+{len(self.plan) - limit} more)")
        return "\n".join(out)

    # -- coverage helpers -----------------------------------------------------
    def all_endpoints(self) -> list:
        seen = []
        for k in ("param_urls", "endpoints", "tier1", "paths"):
            for u in self.surface.get(k, []):
                if isinstance(u, str) and u.startswith("http") and u not in seen:
                    seen.append(u)
        return seen

    def tested_targets(self) -> set:
        return {e.get("target", "") for e in self.ledger if e.get("target")}

    def untested_endpoints(self) -> list:
        tested = self.tested_targets()
        return [u for u in self.all_endpoints() if u not in tested]

    # -- reads (for the planner / reporter) -----------------------------------
    @staticmethod
    def _args_str(args: dict) -> str:
        return " ".join(f"{k}={v}" for k, v in args.items()) if args else ""

    def identities_block(self) -> str:
        if not self.identities:
            return "(none - unauthenticated)"
        return "; ".join(f"{k}=[{' '.join(v)}]" for k, v in self.identities.items())

    def digest(self, url_sample: int = 30) -> str:
        s = self.surface
        out = [
            f"TARGET={self.target}  BASE={self.base_url}",
            f"IDENTITIES: {self.identities_block()}",
            "SURFACE: " + " ".join(f"{k}={len(s.get(k, []))}" for k in _SURFACE),
            f"UNTESTED endpoints: {len(self.untested_endpoints())} / {len(self.all_endpoints())} known",
        ]
        if self.secrets:
            out.append("HARVESTED: " + "; ".join(f"{x.get('kind')}@{x.get('source')}" for x in self.secrets[:8]))
        if self.findings:
            out.append("FINDINGS:")
            for f in sorted(self.findings, key=lambda f: -sev_rank(f.severity))[:25]:
                out.append(f"  [{f.severity}|{f.status}] {f.cls or '?'} {f.title} @ {f.url}")
        sample = self.untested_endpoints()[:url_sample] or self.all_endpoints()[:url_sample]
        if sample:
            out.append("ENDPOINTS (untested first):\n" + "\n".join("  " + u for u in sample))
        if self.notes:
            out.append("NOTES:\n" + "\n".join("  - " + n for n in self.notes[-10:]))
        return "\n".join(out)

    def findings_report(self) -> str:
        if not self.findings:
            return "(no findings)"
        items = sorted(self.findings, key=lambda f: -sev_rank(f.severity))
        return "\n".join(f"[{f.severity}|{f.status}] {f.cls or '?'} :: {f.title} @ {f.url}\n    evidence: {f.evidence}"
                         for f in items)

    def coverage_report(self) -> str:
        counts = {}
        for e in self.ledger:
            counts[e["tool"]] = counts.get(e["tool"], 0) + 1
        sev = {}
        for f in self.findings:
            sev[f.status] = sev.get(f.status, 0) + 1
        out = ["=== ORCA RUN FACTS (machine-generated) ==="]
        out.append("tool calls: " + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
                   + f"  ({len(self.ledger)} total)")
        out.append(f"endpoints: {len(self.all_endpoints())} known, {len(self.untested_endpoints())} untested")
        out.append("findings by status: " + (", ".join(f"{k} {v}" for k, v in sorted(sev.items())) or "none"))
        return "\n".join(out)


# -- shared ingestion helpers (used by several executors) ---------------------

def cls_from_fuzz_title(title: str) -> str:
    for tok in _CLS_BRACKET.findall(title or ""):
        if tok in _VULN_CLS:
            return "bola" if tok == "numeric" else ("error" if tok == "error" else tok)
    return ""


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()

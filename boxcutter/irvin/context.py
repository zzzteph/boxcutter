"""irvin's context - the shared LANDSCAPE plus a machine-parsable, append-only AUDIT TRAIL.

Two parts, both pure data so the whole run serializes to one JSON document:

  - landscape: the current FACTS every agent reads (surface, identities, secrets, findings).
  - trail:     an ordered list of uniform Records, one per agent decision/advice. Every record has the
               SAME shape and an explicit `refs` list pointing at the records it derives from, so the run
               is a causal GRAPH you can walk:

                   suggestion (s..)  <-  verdict inside prioritization (c..)  <-  plan step (p..)  <-  result (x..)

               Nothing is dropped silently: the concluder records a verdict (accept/defer/decline) WITH a
               reason for EVERY suggestion, and every executor result links back to the suggestion that
               caused it. So any agent (or human) can cross-check why an action happened, or why advice was
               declined / deprioritized.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

# id prefixes by record kind - make the trail human- and machine-readable at a glance
_PREFIX = {"suggestion": "s", "skip": "s", "prioritization": "c", "plan": "p", "result": "x",
           "adjustment": "a", "report": "r"}

# executors whose JOB is broad host/page-level mapping, not one exact URL - the commission key for these
# collapses to host (or host+first-path-segment for dirbust) so scheme/trailing-slash/deep-subpath variance
# doesn't defeat the negative-memory gate. Exploit/access executors keep exact-URL keys (an escalation targets
# one precise endpoint, and that precision matters).
_DISCOVERY_EXECUTORS = {"recon", "spa", "dirbust"}


def extract_json(text: str) -> dict:
    """Best-effort parse of the JSON object in an LLM reply (fenced block, then largest span, then scan)."""
    if not text:
        return {}
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if m:
        try:
            o = json.loads(m.group(1))
            if isinstance(o, dict):
                return o
        except json.JSONDecodeError:
            pass
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            o = json.loads(m.group(0))
            if isinstance(o, dict):
                return o
        except json.JSONDecodeError:
            pass
    dec, i = json.JSONDecoder(), text.find("{")
    while i != -1:
        try:
            o, _ = dec.raw_decode(text, i)
            if isinstance(o, dict):
                return o
        except json.JSONDecodeError:
            pass
        i = text.find("{", i + 1)
    return {}


@dataclass
class Record:
    """One entry in the audit trail - identical shape for every agent and phase."""
    id: str
    round: int
    phase: str          # suggest | conclude | plan | execute | report
    role: str           # suggester | concluder | planner | executor | reporter
    agent: str          # the agent's name
    kind: str           # suggestion | skip | prioritization | plan | result | report
    summary: str = ""
    rationale: str = ""                    # WHY - the explainability field
    refs: list = field(default_factory=list)   # ids of records this one derives from (causal links)
    data: dict = field(default_factory=dict)   # kind-specific structured payload
    ts: str = ""


@dataclass
class Context:
    target: str
    base_url: str = ""
    aggressive: bool = True
    brief: str = ""       # operator-supplied context (--context): what the target IS, what's out of scope, etc.
    round: int = 0
    landscape: dict = field(default_factory=dict)
    trail: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    responses: dict = field(default_factory=dict)   # tool argv -> output (filled by the shared runner)
    ledger: list = field(default_factory=list)       # every tool call (filled by the shared runner)
    commissions: dict = field(default_factory=dict)  # "executor|target" -> {runs,findings,produced}: negative memory
    _index: dict = field(default_factory=dict)     # id -> Record
    _seq: dict = field(default_factory=dict)        # (round, prefix) -> counter
    _creds: dict = field(default_factory=dict)      # placeholder -> {label,user,password,login_url}: NEVER rendered
    _auth_signals: list = field(default_factory=list)   # deterministic 401/403 sightings, for the auth suggester

    def __post_init__(self):
        self.landscape.setdefault("target", self.target)
        self.landscape.setdefault("base_url", self.base_url)
        self.landscape.setdefault("surface", {"endpoints": [], "params": [], "graphql": [], "hosts": []})
        self.landscape.setdefault("identities", {})
        self.landscape.setdefault("secrets", [])
        self.landscape.setdefault("findings", [])

    # -- trail ---------------------------------------------------------------
    def _new_id(self, kind: str) -> str:
        p = _PREFIX.get(kind, "e")
        key = (self.round, p)
        self._seq[key] = self._seq.get(key, -1) + 1
        return f"{p}{self.round}.{self._seq[key]}"

    def add_record(self, phase, role, agent, kind, summary="", rationale="", refs=None, data=None) -> Record:
        """Append one decision/advice record to the audit trail."""
        rec = Record(id=self._new_id(kind), round=self.round, phase=phase, role=role, agent=agent,
                     kind=kind, summary=summary, rationale=rationale, refs=list(refs or []),
                     data=data or {}, ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        self.trail.append(rec)
        self._index[rec.id] = rec
        return rec

    def record(self, argv, out):
        """The shared Runner calls ctx.record(argv, out) on every tool call: log it. Kept OUT of the decision
        trail - it's raw tool evidence, not an agent decision."""
        self.responses[tuple(argv)] = out
        self.ledger.append({"tool": argv[0] if argv else "", "target": argv[1] if len(argv) > 1 else ""})

    def get(self, rec_id: str):
        return self._index.get(rec_id)

    def lineage(self, rec_id: str) -> list:
        """Walk refs backward to the root - the full causal chain behind a record (for cross-checking)."""
        chain, seen, frontier = [], set(), [rec_id]
        while frontier:
            rid = frontier.pop(0)
            rec = self._index.get(rid)
            if not rec or rid in seen:
                continue
            seen.add(rid)
            chain.append(rec)
            frontier += rec.refs
        return chain

    def suggester_of(self, suggestion_id: str) -> str:
        rec = self._index.get(suggestion_id)
        return rec.agent if rec else "?"

    # -- commission ledger (negative memory) ---------------------------------
    # A commission is one (executor, target). After it runs we remember whether it PRODUCED anything (a finding
    # or new surface). Re-commissioning a pair that already ran and produced NOTHING is wasted work - the
    # concluder declines it deterministically, and the managers see it so they don't ask again.
    def _norm_target(self, executor: str, target: str) -> str:
        raw = str(target or "").strip() or (self.base_url or "")
        if executor == "auth":
            # session refresh is legitimately re-triggerable every round (the session can expire more than
            # once) - the suggester's own judgment is the gate, not the negative-memory ledger, so scope the
            # key to THIS round only: a repeat WITHIN a round is still caught, a repeat ACROSS rounds isn't.
            return f"{raw.lower()}@round{self.round}"
        if executor not in _DISCOVERY_EXECUTORS:
            return raw.rstrip("/").lower()
        p = urlparse(raw if "://" in raw else f"//{raw}")
        host = (p.hostname or "").lower()
        if not host:
            return raw.rstrip("/").lower()
        if executor == "dirbust":
            seg = p.path.strip("/").split("/", 1)[0].lower()
            return f"{host}/{seg}" if seg else host
        return host   # recon/spa: same host = same commission, regardless of scheme/path/trailing slash

    def log_commission(self, executor: str, target: str, handoff: dict, merged: dict | None = None):
        """Record one commission's outcome. `merged` (from merge_handoff) carries how much was ACTUALLY NEW -
        the signal `is_dead_commission` needs. Without it, falls back to raw handoff counts (still useful for
        one-off callers, but re-reporting already-known surface would wrongly look like progress)."""
        key = f"{executor}|{self._norm_target(executor, target)}"
        slot = self.commissions.setdefault(key, {"runs": 0, "findings": 0, "produced": 0})
        slot["runs"] += 1
        m = merged or {}
        slot["findings"] += m.get("new_findings", len(handoff.get("findings") or []))
        art = handoff.get("artifacts") or {}
        slot["produced"] += m.get("new_surface", len(art.get("endpoints") or []) + len(art.get("tokens") or []))

    def was_committed(self, executor: str, target: str) -> bool:
        return f"{executor}|{self._norm_target(executor, target)}" in self.commissions

    def is_dead_commission(self, executor: str, target: str) -> bool:
        """True if (executor, target) already ran AND produced nothing (no finding, no new surface)."""
        slot = self.commissions.get(f"{executor}|{self._norm_target(executor, target)}")
        return bool(slot and slot["runs"] and not slot["findings"] and not slot["produced"])

    def low_yield_lanes(self, min_runs: int = 2) -> dict:
        """Per-EXECUTOR (not per-target) aggregate: lanes that have run >=min_runs times total across all
        targets and never produced a finding. Distinct from is_dead_commission, which is per-target and also
        gates on 'produced' surface - a lane like dirbust can keep mapping a few new paths every run (so no
        single commission ever goes dead) while still converting NONE of them into an actual finding. This is
        the cost/yield signal for that case."""
        agg = {}
        for key, slot in self.commissions.items():
            ex = key.split("|", 1)[0]
            a = agg.setdefault(ex, {"runs": 0, "findings": 0})
            a["runs"] += slot["runs"]
            a["findings"] += slot["findings"]
        return {ex: a for ex, a in agg.items() if a["runs"] >= min_runs and not a["findings"]}

    def low_yield_render(self) -> str:
        lanes = self.low_yield_lanes()
        return "\n".join(f"  {ex}: {a['runs']} run(s) across target(s), 0 findings so far"
                         for ex, a in lanes.items())

    def commission_target(self, step: dict) -> str:
        """The target a plan step commits to: an explicit `target` (escalations set it), else the originating
        suggestion's target, else the step args. The ledger key and the thinner both derive it the same way."""
        if step.get("target"):
            return step["target"]
        sug = self.get(step.get("ref")) if step.get("ref") else None
        if sug:
            return sug.data.get("target") or ""
        a = step.get("args") or {}
        return a.get("url") or a.get("target") or ""

    def dead_commissions_render(self) -> str:
        dead = [k for k, v in self.commissions.items() if v["runs"] and not v["findings"] and not v["produced"]]
        return "\n".join("  " + k.replace("|", " on ", 1) for k in dead)

    def round_suggestions(self) -> list:
        return [r for r in self.trail if r.round == self.round and r.kind == "suggestion"]

    # -- council track record (success -> priority) --------------------------
    def credibility(self) -> dict:
        """Per-suggester record: how much advice they gave, how much was accepted, how much produced a
        finding. A profile that keeps paying off earns priority; one that never does loses it."""
        score, owner = {}, {}

        def slot(n):
            return score.setdefault(n, {"suggested": 0, "accepted": 0, "hits": 0})

        for r in self.trail:
            if r.kind == "suggestion":
                owner[r.id] = r.agent
                slot(r.agent)["suggested"] += 1
            elif r.kind == "prioritization":
                for v in r.data.get("verdicts", []):
                    if v.get("verdict") == "accept" and owner.get(v.get("ref")):
                        slot(owner[v["ref"]])["accepted"] += 1
            elif r.kind == "result" and r.data.get("findings"):
                for ref in r.refs:
                    if owner.get(ref):
                        slot(owner[ref])["hits"] += 1
        return score

    def credibility_render(self) -> str:
        sc = self.credibility()
        if not sc:
            return "(no track record yet - first round)"
        rows = sorted(sc.items(), key=lambda kv: (-kv[1]["hits"], -kv[1]["accepted"]))
        return "\n".join(f"  {n}: {d['hits']} finding(s) from {d['accepted']} accepted / {d['suggested']} "
                         f"suggested" for n, d in rows)

    def advice_outcomes(self, name: str, last: int = 6) -> str:
        """One profile's own advice history and what came of it - so it can argue from / build on it. Each
        line names exactly what ran and what it produced (from the commission ledger), so a repeat of a brief
        that came back empty is impossible to miss - not just a verdict tag with no outcome attached."""
        sug_ids = [r.id for r in self.trail if r.kind == "suggestion" and r.agent == name]
        if not sug_ids:
            return "(none yet)"
        verdict = {}
        for r in self.trail:
            if r.kind == "prioritization":
                for v in r.data.get("verdicts", []):
                    verdict[v.get("ref")] = v
        hits = {ref for r in self.trail if r.kind == "result" and r.data.get("findings") for ref in r.refs}
        out = []
        for sid in sug_ids[-last:]:
            s, v = self.get(sid), verdict.get(sid, {})
            tag = v.get("verdict", "pending") + ("+FINDING" if sid in hits else "")
            line = f"  {sid} {s.summary}: {tag}" + (f" — {v.get('why')}" if v.get("why") else "")
            action, target = s.data.get("action"), s.data.get("target")
            slot = self.commissions.get(f"{action}|{self._norm_target(action, target)}") if action else None
            if slot:
                line += f"  (ran: {slot['findings']} finding(s), {slot['produced']} new surface item(s))"
            out.append(line)
        return "\n".join(out)

    # -- landscape writes ----------------------------------------------------
    def add_urls(self, urls) -> int:
        """Dedup into the surface; returns how many were genuinely NEW (not already mapped) - the signal
        log_commission needs to tell 'this run found new ground' from 're-reported what we already knew'."""
        s = self.landscape["surface"]
        added = 0
        for u in urls:
            if not (isinstance(u, str) and u.startswith(("http://", "https://"))):
                continue
            bucket = "params" if "?" in u else "endpoints"
            if u not in s[bucket]:
                s[bucket].append(u)
                added += 1
            host = (urlparse(u).hostname or "").lower()
            if host and host not in s["hosts"]:
                s["hosts"].append(host)
        return added

    def add_graphql(self, urls):
        s = self.landscape["surface"]
        for u in urls:
            if u and u not in s["graphql"]:
                s["graphql"].append(u)

    def add_identity(self, label, headers, source="") -> bool:
        """Returns True if this exact header set is genuinely new (not already held under some label)."""
        is_new = headers not in self.landscape["identities"].values()
        self.landscape["identities"][label] = headers
        if source:
            self.note(f"identity '{label}' from {source}")
        return is_new

    def add_secret(self, kind, value, source=""):
        secs = self.landscape["secrets"]
        if value and value not in {x.get("value") for x in secs}:
            secs.append({"kind": kind, "value": value, "source": source})

    # -- credentials (session management) -------------------------------------
    # Stored PRIVATELY - never rendered into landscape_digest/recent_trail/any prompt or the trail JSON. An
    # agent that needs to log in gets only a placeholder token to pass as a tool argument; the real value is
    # substituted just before the call actually dispatches (see agents/base.py Executor._rewrite_call).
    def store_creds(self, label: str, user: str, password: str, login_url: str) -> str:
        placeholder = f"__STORED_CREDS_{label}__"
        self._creds[placeholder] = {"label": label, "user": user, "password": password, "login_url": login_url}
        return placeholder

    def creds_for_placeholder(self, placeholder: str) -> str:
        c = self._creds.get(placeholder)
        return f"{c['user']}:{c['password']}" if c else ""

    def creds_login_url(self, label: str) -> str:
        for c in self._creds.values():
            if c["label"] == label:
                return c["login_url"]
        return ""

    def placeholder_for(self, label: str) -> str:
        """The placeholder token for an identity that already has stored creds, or '' if it has none - the
        one place that knows the placeholder's format, so callers never hardcode it."""
        for placeholder, c in self._creds.items():
            if c["label"] == label:
                return placeholder
        return ""

    def has_creds(self, label: str) -> bool:
        return any(c["label"] == label for c in self._creds.values())

    # -- auth signal (deterministic evidence for the auth suggester) ----------
    # A 401/403 is NOT automatically "the session expired" - a legitimately-protected endpoint returns the
    # same codes. That judgment stays with the agent; this just makes the raw evidence cheap to see instead of
    # requiring the model to notice it buried in individual tool outputs.
    def note_auth_signal(self, status: int, url: str) -> None:
        if status in (401, 403):
            self._auth_signals.append({"status": status, "url": url, "round": self.round})

    def auth_signal_render(self, n: int = 10) -> str:
        if not self._auth_signals:
            return ""
        lines = "\n".join(f"  [{s['status']}] {s['url']} (round {s['round']})" for s in self._auth_signals[-n:])
        return f"AUTH SIGNALS ({len(self._auth_signals)} total 401/403 response(s) seen so far):\n{lines}"

    def add_finding(self, f: dict, by: str = "", refs=None) -> dict:
        """Dedup by (title,url); keep the highest severity. Stamps the originating suggestion refs."""
        title = (f.get("title") or "").strip()
        url = f.get("url") or ""
        if not title:
            return {}
        for g in self.landscape["findings"]:
            if g["title"].lower() == title.lower() and g["url"] == url:
                return g
        rec = {"id": f"f{len(self.landscape['findings']) + 1}", "severity": str(f.get("severity", "info")).title(),
               "title": title, "url": url, "cls": str(f.get("cls", "")).lower(),
               "evidence": str(f.get("evidence", ""))[:120], "status": f.get("status", "verified"),
               "by": by, "from": list(refs or [])}
        self.landscape["findings"].append(rec)
        return rec

    def merge_handoff(self, handoff: dict, by: str, refs=None) -> dict:
        """Fold an executor's structured handoff into the landscape, stamping the causal refs on findings.
        Returns {"new_findings", "new_surface"}: how much of this handoff was ACTUALLY NEW after dedup against
        the existing landscape - log_commission's input for telling real progress from a re-reported result."""
        before = len(self.landscape["findings"])
        for f in handoff.get("findings") or []:
            if isinstance(f, dict):
                self.add_finding(f, by=by, refs=refs)
        new_findings = len(self.landscape["findings"]) - before
        art = handoff.get("artifacts") or {}
        new_urls = self.add_urls(art.get("endpoints") or [])
        new_identities = 0
        for i, tok in enumerate(art.get("tokens") or []):
            if isinstance(tok, dict) and tok.get("header"):
                # "label" lets an executor target-replace a SPECIFIC existing identity (e.g. the auth
                # executor refreshing identity "A") instead of always minting a new H1/H2/... alongside it.
                label = tok.get("label") or f"H{i + 1}"
                if self.add_identity(label, ["--header", tok["header"]], tok.get("source", by)):
                    new_identities += 1
        for n in art.get("notes") or []:
            self.note(n)
        return {"new_findings": new_findings, "new_surface": new_urls + new_identities}

    def note(self, msg):
        if msg and msg not in self.notes:
            self.notes.append(msg)

    # -- reads (for the agents) ---------------------------------------------
    def landscape_digest(self, sample: int = 25) -> str:
        s = self.landscape["surface"]
        ids = self.landscape["identities"]
        out = []
        if self.brief:
            # operator-supplied grounding (--context): what the target IS, what's out of scope, what to focus
            # on. Read by every suggester/concluder/executor via this one digest, so it needs no per-prompt wiring.
            out.append(f"OPERATOR BRIEFING: {self.brief}")
        out += [
            f"TARGET={self.target}  BASE={self.base_url}  ROUND={self.round}",
            f"IDENTITIES: {', '.join(ids) if ids else '(none - unauthenticated)'}",
            f"SURFACE: endpoints={len(s['endpoints'])} params={len(s['params'])} "
            f"graphql={len(s['graphql'])} hosts={len(s['hosts'])}",
        ]
        if self.landscape["secrets"]:
            out.append("SECRETS: " + "; ".join(f"{x['kind']}@{x.get('source', '')}"
                                                for x in self.landscape["secrets"][:6]))
        if self.landscape["findings"]:
            out.append("FINDINGS:")
            for f in self.landscape["findings"][:20]:
                out.append(f"  [{f['severity']}|{f['status']}] {f['cls'] or '?'} {f['title']} @ {f['url']}")
        urls = (s["params"] + s["endpoints"])[:sample]
        if urls:
            out.append("ENDPOINTS (sample):\n" + "\n".join("  " + u for u in urls))
        return "\n".join(out)

    def recent_trail(self, n: int = 40) -> str:
        if not self.trail:
            return "(nothing yet - first round)"
        out = []
        for r in self.trail[-n:]:
            line = f"  {r.id} [{r.phase}/{r.agent}] {r.summary}"
            if r.rationale:
                line += f"  — {r.rationale}"
            out.append(line)
        return "\n".join(out)

    def to_json(self, indent: int = 2) -> str:
        """The full machine-parsable run: landscape + the entire decision trail."""
        return json.dumps({
            "target": self.target, "base_url": self.base_url, "rounds": self.round,
            "landscape": self.landscape,
            "commissions": self.commissions,
            "trail": [asdict(r) for r in self.trail],
        }, indent=indent)

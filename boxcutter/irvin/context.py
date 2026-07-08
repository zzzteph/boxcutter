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
from urllib.parse import parse_qsl, urlparse

# id prefixes by record kind - make the trail human- and machine-readable at a glance
_PREFIX = {"suggestion": "s", "skip": "s", "prioritization": "c", "plan": "p", "result": "x",
           "adjustment": "a", "report": "r"}

# executors whose commission key collapses to host (recon/spa) or host+first-path-seg (dirbust).
# all other executors normalize to path-family + param-names (no param values), so probe-value
# variants of the same endpoint (/?id=1 vs /?id=2, /eam/vib?id=/etc/issue vs /eam/vib?id=1) map
# to the same commission key and are correctly gated as one engagement unit.
_HOST_EXECUTORS = {"recon", "spa"}

# exploitation lanes where a commission legitimately has TWO phases: DETECT (confirm + minimal proof) then
# EXPLOIT (go deeper - dump the DB, read more files, build the chain). A CONFIRMED finding on such a lane's
# exact target earns ONE re-commission so the negative-memory gate doesn't conflate the two - otherwise a
# detection run counts as "already ran" on the target and the follow-up post-exploitation dump is gated
# forever, so the engagement never weaponizes a vuln it already confirmed.
_EXPLOIT_EXECUTORS = {"sqli", "xss", "path-traversal"}

# tools that genuinely take time (a battery of requests, a brute, a browser render). If one of these returns in
# a blink, it almost certainly NO-OP'd - errored on a bad argument, hit an empty target, or was skipped - so the
# timing is the tell that a command didn't really do its work (a false-negative risk). http-request/screenshot
# are legitimately fast and excluded.
_HEAVY_TOOLS = {"fuzz", "sqlmap", "dirsearch", "dirb", "path-fuzz", "nuclei", "katana-crawl", "git-extract",
                "subfinder", "browser-crawl", "browser-actions", "visual-driver"}

# coverage: which vuln-lane must have run over an endpoint's STRUCTURAL FAMILY for it to count as tested. A
# family collapses id-like path segments to {id} and keys on the set of param NAMES, so /user/1?tab and
# /user/2?tab are one family - testing one member covers the rest (the same 'same-functionality' equivalence
# the runner uses to skip redundant tests and the consolidator uses to merge findings).
_ID_SEG = re.compile(r"\A(?:\d+|[0-9a-fA-F]{8,}|[0-9A-Za-z_-]{20,})\Z")
_ID_PARAM = {"id", "uid", "userid", "user", "username", "account", "acct", "order", "orderid", "doc", "docid",
             "file", "fileid", "pid", "num", "key", "ref", "item", "itemid", "record", "rid", "gid", "oid",
             "cid", "eid", "pageid", "page_id", "product", "productid"}


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
    leads: list = field(default_factory=list)         # cross-lane {cls,url,param,why,evidence} handed to specialists
    round_summary: str = ""    # the summarizer's briefing of the last round (executors_summary -> council)
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

    def record(self, argv, out, ms=None, cached=False):
        """The shared Runner calls ctx.record(argv, out) on every tool call: log it. Kept OUT of the decision
        trail - it's raw tool evidence, not an agent decision. `ms` is the real dispatch time (None on a cache
        hit); `ok` is parsed from the envelope. Together they make a no-op fast failure (a heavy tool that
        errored on bad args and returned in ~0ms) visible in the trail instead of passing as clean work."""
        self.responses[tuple(argv)] = out
        ok = None
        try:
            env = json.loads(out)
            if isinstance(env, dict):
                ok = bool(env.get("success", True)) and not env.get("error")
        except Exception:  # noqa: BLE001 - non-JSON output: leave ok unknown
            ok = None
        self.ledger.append({"tool": argv[0] if argv else "", "target": argv[1] if len(argv) > 1 else "",
                            "round": self.round,       # round tag lets the actions graph group commands per round
                            "ms": ms, "cached": cached, "ok": ok})

    def suspect_commands(self, fast_ms: int = 1500) -> list:
        """Heavy tools (expected to take real time) that returned suspiciously FAST or errored - the timing
        tell that a command NO-OP'd (bad args, empty target, immediate rejection) instead of doing its work.
        Cache hits are excluded (their instant return is expected)."""
        out = []
        for e in self.ledger:
            if e.get("cached") or e.get("tool") not in _HEAVY_TOOLS:
                continue
            ms, ok = e.get("ms"), e.get("ok")
            if ok is False or (isinstance(ms, int) and ms < fast_ms):
                out.append(e)
        return out

    def command_health_render(self, n: int = 8) -> str:
        sus = self.suspect_commands()
        if not sus:
            return ""
        lines = "\n".join(f"  {e['tool']} {e.get('target', '')} ({e.get('ms')}ms"
                          + (", ERROR" if e.get("ok") is False else "") + ")" for e in sus[-n:])
        return ("SUSPECT COMMANDS (a heavy tool returned in a blink or errored - it likely NO-OP'd on a bad "
                f"call and its 'nothing found' is not trustworthy; re-run it correctly before closing the lane):"
                f"\n{lines}")

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
        p = urlparse(raw if "://" in raw else f"//{raw}")
        host = (p.hostname or "").lower()
        if not host:
            return raw.rstrip("/").lower()
        if executor in _HOST_EXECUTORS:
            return host   # recon/spa: same host = same commission, regardless of scheme/path/trailing slash
        if executor == "dirbust":
            seg = p.path.strip("/").split("/", 1)[0].lower()
            return f"{host}/{seg}" if seg else host
        # all other executors (exploitation, triage, access, exposure): normalize to endpoint FAMILY -
        # path with id-segments collapsed + sorted param NAMES (no values). This gates probe-value
        # variants of the same sink as one commission: sqli on /?id=1 == sqli on /?id=2 == same gate.
        segs = ["{id}" if _ID_SEG.match(s) else s.lower() for s in p.path.strip("/").split("/") if s]
        params = sorted({k.lower() for k, _ in parse_qsl(p.query)})
        path_key = "/".join(segs)
        param_key = f"[{','.join(params)}]" if params else ""
        family = f"{host}/{path_key}" if path_key else host
        return f"{family}{param_key}"

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

    def allows_deepening(self, executor: str, target: str) -> bool:
        """True if an EXPLOITATION lane already CONFIRMED a finding on this exact target and has run there only
        once - it earns a single re-commission to go DEEPER (post-exploitation extraction beyond the minimal
        proof the detection run filed). Bounded to one pass (runs == 1) so the negative-memory gate can never
        loop on it, and gated to lanes with a real detect->exploit split so a discovery re-run isn't waved
        through."""
        if executor not in _EXPLOIT_EXECUTORS:
            return False
        slot = self.commissions.get(f"{executor}|{self._norm_target(executor, target)}")
        return bool(slot and slot["runs"] == 1 and slot["findings"] > 0)

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

    def all_commissions_render(self) -> str:
        """Compact one-liner per (executor, endpoint-family) showing what every lane ran and what it produced.
        Shown to every suggester so they have full cross-lane visibility into past work - the cooperative
        contract: check this before advising so you never re-suggest something another lane already covered."""
        if not self.commissions:
            return "(nothing run yet)"
        lines = []
        for key, slot in sorted(self.commissions.items()):
            ex, _, tgt = key.partition("|")
            parts = []
            if slot["findings"]:
                parts.append(f"{slot['findings']} finding(s)")
            if slot["produced"]:
                parts.append(f"{slot['produced']} new surface")
            if not parts:
                parts.append("nothing new")
            runs = f" [x{slot['runs']}]" if slot["runs"] > 1 else ""
            lines.append(f"  {ex} on {tgt}{runs}: {', '.join(parts)}")
        return "\n".join(lines)

    def executor_trail(self, n: int = 30) -> str:
        """The last N executor RESULTS only - no suggest/conclude/plan noise. Gives suggesters a clean
        view of what specialists actually found and did, not every pipeline decision in between."""
        results = [r for r in self.trail if r.kind == "result"][-n:]
        if not results:
            return "(no executor results yet)"
        out = []
        for r in results:
            line = f"  {r.id} [r{r.round}|{r.agent}] {r.summary}"
            if r.rationale:
                line += f"  — {r.rationale}"
            out.append(line)
        return "\n".join(out)

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

    def advice_outcomes(self, name: str) -> str:
        """One profile's own advice history and what came of it - so it can argue from / build on it. Each
        line names exactly what ran and what it produced (from the commission ledger), so a repeat of a brief
        that came back empty is impossible to miss - not just a verdict tag with no outcome attached.
        Shows ALL suggestions (no cap) so early-round commissions never silently fall off the profile's
        own history and cause re-suggestions of work already done."""
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
        for sid in sug_ids:
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

    # -- secret typing tokens (for coordinate/visual login) -------------------
    # browser-login takes creds as one "user:pass" placeholder, but a VISUAL login types the username and the
    # password into SEPARATE fields, so it needs two distinct tokens. The model types the tokens; the real
    # values are substituted only at dispatch (in the executor's _rewrite_call), so they never reach the model.
    def secret_tokens(self, label: str) -> tuple:
        return f"__USER_{label}__", f"__PASS_{label}__"

    def resolve_secret_tokens(self, text: str) -> str:
        """Replace every __USER_x__/__PASS_x__ token with the real username/password for any identity that has
        stored creds. A no-op on text without a token (the common case), so it's safe to run on every arg."""
        if not isinstance(text, str) or ("__USER_" not in text and "__PASS_" not in text):
            return text
        for c in self._creds.values():
            u_tok, p_tok = self.secret_tokens(c["label"])
            text = text.replace(u_tok, c["user"]).replace(p_tok, c["password"])
        return text

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
        new_leads = 0
        have = {(str(x.get("cls", "")).lower(), x.get("url") or x.get("target", ""), x.get("param", ""))
                for x in self.leads}
        for ld in art.get("leads") or []:
            if isinstance(ld, dict) and ld.get("cls") and (ld.get("url") or ld.get("target")):
                key = (str(ld["cls"]).lower(), ld.get("url") or ld.get("target", ""), ld.get("param", ""))
                if key not in have:
                    have.add(key)
                    self.leads.append({**ld, "by": by, "round": self.round})
                    new_leads += 1
        for n in art.get("notes") or []:
            self.note(n)
        # a new cross-lane LEAD is fresh ground too - it keeps the loop alive so the specialist gets its turn
        return {"new_findings": new_findings, "new_surface": new_urls + new_identities + new_leads}

    def note(self, msg):
        if msg and msg not in self.notes:
            self.notes.append(msg)

    # -- coverage (squeeze every endpoint) -----------------------------------
    # An endpoint is "covered" when every lane APPLICABLE TO ITS SHAPE has run against its structural family:
    # injection (web-vuln-triage) applies to anything carrying input (a query param or an {id} path segment);
    # access-control applies to anything referencing an object (an {id} path segment or an id-like param). A
    # parameterless, id-less static path owes neither - recon/exposure already covered it. Coverage is counted
    # over FAMILIES, not raw URLs, so testing /user/1 covers /user/2.../user/999 and a dirbust-exploded surface
    # doesn't explode the work.
    def _family(self, url: str) -> str:
        p = urlparse(url if "://" in url else f"http://{url}")
        segs = ["{id}" if _ID_SEG.match(s) else s.lower() for s in p.path.strip("/").split("/") if s]
        params = sorted({k.lower() for k, _ in parse_qsl(p.query)})
        return f"{(p.hostname or '').lower()}/{'/'.join(segs)}[{','.join(params)}]"

    @staticmethod
    def _inj_applies(url: str) -> bool:
        p = urlparse(url if "://" in url else f"http://{url}")
        return bool(p.query) or any(_ID_SEG.match(s) for s in p.path.strip("/").split("/") if s)

    @staticmethod
    def _acc_applies(url: str) -> bool:
        p = urlparse(url if "://" in url else f"http://{url}")
        if any(_ID_SEG.match(s) for s in p.path.strip("/").split("/") if s):
            return True
        return any(k.lower() in _ID_PARAM for k, _ in parse_qsl(p.query))

    def coverage_map(self) -> dict:
        """{lane: {applicable, tested, owed:[example urls]}} over the surface's structural families. `tested`
        means the lane's commission ledger shows a run on some member of that family."""
        lanes = {"web-vuln-triage": self._inj_applies, "sqli": self._inj_applies,
                 "xss": self._inj_applies, "path-traversal": self._inj_applies,
                 "access-control": self._acc_applies}
        fams: dict = {}
        for u in self.landscape["surface"]["params"] + self.landscape["surface"]["endpoints"]:
            fams.setdefault(self._family(u), u)               # one example URL per family
        tested = {ln: set() for ln in lanes}
        for key in self.commissions:
            ex, _, tgt = key.partition("|")
            if ex in tested and tgt:
                tested[ex].add(self._family(tgt))
        out = {}
        for ln, applies in lanes.items():
            applicable = {f: ex for f, ex in fams.items() if applies(ex)}
            owed = [ex for f, ex in applicable.items() if f not in tested[ln]]
            out[ln] = {"applicable": len(applicable), "tested": len(applicable) - len(owed), "owed": owed}
        return out

    def coverage_render(self, sample: int = 8) -> str:
        cm = self.coverage_map()
        if not any(v["applicable"] for v in cm.values()):
            return ""
        lines = ["COVERAGE (structural families - testing one member covers the family; squeeze every family):"]
        for ln, v in cm.items():
            if not v["applicable"]:
                continue
            head = f"  {ln}: {v['tested']}/{v['applicable']} families tested"
            if v["owed"]:
                head += "; OWED: " + ", ".join(v["owed"][:sample]) + (" ..." if len(v["owed"]) > sample else "")
            else:
                head += " - COMPLETE"
            lines.append(head)
        return "\n".join(lines)

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
        if self.leads:
            # cross-lane leads raised by executors - an escalatable class is auto-commissioned to its specialist;
            # any OTHER lead (e.g. an exposed admin/login panel with no dedicated exploiter) is here for a
            # manager to pick up and commission the right desk. Don't let a raised lead sit untested.
            out.append("OPEN LEADS (raised by an executor for another desk - commission the owner):")
            for ld in self.leads[:12]:
                out.append(f"  [{str(ld.get('cls', '?')).lower()}] {ld.get('url') or ld.get('target', '')}"
                           + (f" ({ld['param']})" if ld.get("param") else "")
                           + (f" - {ld['why']}" if ld.get("why") else "") + f"  <- {ld.get('by', '?')}")
        cov = self.coverage_render()
        if cov:
            out.append(cov)
        if self.round_summary:
            # the summarizer's briefing of what the executors established last round + the top unfinished
            # business - the executors_summary -> council edge, read here so the council acts on it next round
            out.append(f"PREVIOUS ROUND BRIEFING (from the summarizer):\n{self.round_summary}")
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

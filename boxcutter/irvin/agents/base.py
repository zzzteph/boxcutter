"""irvin agent bases - the two pluggable agent TYPES.

  Suggester : a profile expert. Reads the landscape, advises in its lane (or SKIPS). Pure judgement,
              one-shot LLM call, returns structured advice. Never touches tools.
  Executor  : a working agent. Drives boxcutter in its own tool-calling loop to DO one job, then VERIFIES
              its own output (dedup / denoise / validate) before handing back - the next stage trusts it
              blindly, so quality is the executor's responsibility.

Both return plain dicts; the pipeline records them into the context and streams them. Decision roles
(concluder/planner/reporter) live in control.py.
"""

from __future__ import annotations

import json
import re
import sys
from urllib.parse import urlsplit

from ...core import agentlog
from ...core.envelope import harvest_images
from ...tools import toolschema
from ..context import extract_json
from ..verify import reproduce

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_APIKEY = re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|secret)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9._-]{16,})")

# A discovered admin/management/privileged PANEL must not just sit in the endpoint list - that is exactly how a
# found panel gets orphaned: a discovery tool tags it and no lane ever pursues it. Turn it into a `panel` LEAD
# so EXPOSURE is commissioned to report the reachable admin interface. Deterministic: it does NOT depend on the
# model choosing to raise the lead or a manager choosing to pick it up.
_PANEL_RE = re.compile(r"/(?:admin(?:istrator)?|manage(?:r|ment)?|dashboard|console|backend|cpanel|wp-admin|"
                       r"phpmyadmin|adminer|controlpanel|panel)(?:/|$|\?|\.)", re.I)


def _panel_leads(endpoints) -> list:
    """A `panel` lead for every discovered admin/management panel path, so a reachable privileged surface is
    always handed to EXPOSURE to report, instead of being left in the endpoint list untested."""
    leads, seen = [], set()
    for e in endpoints or []:
        url = str(e).split()[0]                    # discovery tools may emit "url status class"; take the URL
        if not url.startswith(("http://", "https://")):
            continue
        if _PANEL_RE.search(urlsplit(url).path) and url not in seen:
            seen.add(url)
            leads.append({"cls": "panel", "url": url, "param": "",
                          "evidence": "admin/management panel path reachable from outside",
                          "why": "a management/admin panel is reachable - EXPOSURE should report it "
                                 "(login-gated = Low attack surface; a working console reachable without login "
                                 "= High); do not leave it as just an endpoint"})
    return leads

_EXEC_BASE = """You are a PROFESSIONAL penetration tester inside IRVIN, an autonomous web/API bug-hunter
PIPELINE, working ONE specialism - your area is defined under 'Your role' below. A manager (a suggester) has
COMMISSIONED you to settle a specific question in that area; you answer ONLY with results you have VERIFIED -
never a hunch handed back as fact. Bring real tradecraft to it: act with intent, reason from the evidence in
front of you, and be exhaustive IN YOUR LANE. The boxcutter tools are your INSTRUMENTS, not your job - use them
to accomplish your objective, then VERIFY your own output, then stop. Act ONLY through the boxcutter tools
provided (never PUT/PATCH/DELETE, never docker/shell). Reuse the strongest identity on every request.

TOOL DISCIPLINE: each tool's own arguments are the only ones it accepts - the schema won't let you pass
anything else, so there is nothing to invent. If a call comes back empty or with an error, fix the invocation
- do not repeat the same bad call.

STAY GROUNDED: act on the MAPPED surface (paths/endpoints already in the engagement state) plus, at most, a
small fixed set of STANDARD well-known sensitive paths (/.git/, /.env, /config.php, /backup.zip, /admin/,
/debug). Do NOT invent product/application names or deep sub-trees with no evidence - a fingerprint, a link,
or a discovered path. If a base path returns 404, do NOT probe paths beneath it (don't chase /mantisBT/, then
/mantisBT/config/, /mantisBT/admin/ when /mantisBT/ does not exist). Guessed probes that 404 are wasted work.

VERIFY before you hand back - you OWN your output, the next stage trusts it blindly: dedup, strip noise and
false positives, and keep only what you can stand behind (e.g. 100 dirbust hits -> drop soft-404s/dupes and
return the live, distinct ones; a "BOLA" that is byte-identical for every id is public, not a finding).

STAY IN YOUR LANE, RAISE LEADS FOR THE REST: test and file FINDINGS only for YOUR specialism. If, while doing
your job, you OBSERVE a vulnerability of a DIFFERENT class - e.g. you are access-control and a parameter throws
a SQL error / DB stack trace, a page reflects your input, or an endpoint reads a file - do NOT test or exploit
it yourself and do NOT file it as one of YOUR findings. RAISE it as a typed lead in artifacts.leads so the
specialist that OWNS it (sqli, xss, path-traversal, ...) gets commissioned on it automatically. A cross-lane
observation you drop into a note is LOST; a lead is how it reaches the right desk.

End with ONE fenced ```json block and nothing after it:
{"findings":[{"severity":"High|Medium|Low","title":"...","url":"...","cls":"sqli|xss|bola|bfla|exposure|secret|lfi|rce|...","evidence":"<=100 chars verbatim, redacted"}],
 "artifacts":{"endpoints":["<url>"],"tokens":[{"header":"Authorization: Bearer ...","source":"<url>"}],"leads":[{"cls":"sqli|xss|lfi|rce|...","url":"<url incl. the parameter>","param":"<name>","evidence":"<=100 chars, e.g. the exact DB error>","why":"<why it looks like this class - a class OUTSIDE your lane>"}],"notes":["..."]},
 "verification":{"raw":<int raw results seen>,"kept":<int kept>,"dropped":<int discarded as noise/dupes/false>,"validated":true,"notes":"how you deduped/denoised/validated"}}"""

# Independent re-test prompt: each executor re-checks its OWN findings from scratch with its own tools.
# The bar is DELIBERATELY high: IRVIN's report must stand on its own with NO human re-verification, so a
# finding is confirmed only on concrete, reproduced proof of impact - never a hunch or a status code.
_VERIFY_BASE = """You are INDEPENDENTLY VERIFYING a candidate finding a previous pass reported. Trust nothing -
assume it is a FALSE POSITIVE until you prove otherwise. Using ONLY your tools, reproduce it FROM SCRATCH and
obtain CONCRETE, DECISIVE proof of impact - the kind a reviewer would accept without re-testing:
- SQLi -> extract real data (db version, a row, a table/column name) or a deterministic boolean/time oracle.
- BOLA/IDOR -> return ANOTHER user's data for an object you do not own, and quote the cross-user field.
- exposure/secret -> retrieve the ACTUAL sensitive content (source, key, config), not a 200 or a name match.
- XSS/SSTI -> show the payload reflected UNESCAPED in an executing context (or template math evaluated).
- RCE/LFI -> show command output or file contents you should not be able to read.
A generic 200, a soft-404, a catch-all page, a template/banner match, or "looks like" is NOT proof.
If you cannot produce decisive fresh evidence, set confirmed=false. When in doubt, refute.

End with ONE fenced ```json block, nothing after it:
{"confirmed": true, "evidence": "<=120 chars of the DECISIVE fresh proof, redacted", "reason": "the exact reproduction (request/step) and why this is conclusive"}"""

# Agentic EXISTENCE check: a path-guessing executor re-verifies its OWN discovered paths before they spread.
# A 200 is NOT proof a path exists - many hosts are a CATCH-ALL / soft-404 (Caddy `try_files {path} /index.php`,
# an SPA, any framework that 200s on a miss) that returns the SAME page for every path, real or not. The
# executor must fingerprint that behaviour and drop the fallbacks (ghosts) itself.
_GHOST_VERIFY = """You are RE-VERIFYING which of YOUR discovered paths on one host ACTUALLY EXIST as DISTINCT
resources. Do NOT trust an HTTP 200: many servers route EVERY path through ONE front controller (Caddy
`try_files {path} /index.php`, an SPA, a PHP app whose index.php only reads the query string) - so a made-up
path returns 200 and the SAME handler runs. A path 'exists' only if its response is MATERIALLY DIFFERENT from
that catch-all AND that difference comes from the PATH, not from the QUERY STRING.

THE QUERY-STRING TRAP (this is the whole point): if a candidate carries a query (?id=..., ?url=...), the QUERY -
not the PATH - may be what makes it look 'different'. An index.php doing `...where id=$_GET['id']` returns the
SAME SQL error / the SAME content for ANY path carrying that query, real or fake. So `/bugs/eam/vib?id=1`,
`/mantis/verify.php?id=1`, `/verify.php?id=1` and `/totally-fake-9a7c?id=1` are ONE handler reached through many
routes - at most ONE of those paths is a real resource; the rest are just the front controller, and must be
dropped as GHOSTS even though the query makes them look alive.

Work through it with http-request (reuse the strongest identity every request):
1. BARE catch-all: request two DIFFERENT random paths with NO query (e.g. /<rand-a>, /<rand-b>). Record their
   status/title/body shape. If they 404/error honestly, the host 404s - then any non-error candidate is real.
2. QUERY control: for EACH distinct query string among the candidates, fingerprint the catch-all WITH that
   query - request a RANDOM nonexistent path carrying the SAME query (e.g. /<rand>?id=/etc/issue, /<rand>?id=1).
   This is the real control for query-driven differences.
3. CLASSIFY each candidate from the fetched responses:
   - Fetch the candidate PATH WITHOUT its query. If THAT already differs from the bare catch-all (a distinct
     title/form/file/JSON, a login page, real content), the PATH is a real resource -> REAL.
   - Otherwise compare `path?query` to `random-path?same-query` from step 2. If they MATCH, the difference is
     entirely query-driven and the path is just the front controller -> GHOST. It is REAL only if `path?query`
     differs from `random?same-query` (the path itself changes the behavior).
   The site ROOT "/" is always REAL.
Be strict: a path whose BARE form looks like the catch-all AND whose query behavior matches a random path's is a
GHOST - drop it no matter what error or content the query produces. Decide only from fetched responses.

End with ONE fenced ```json block and nothing after it:
{"real": ["<url that is a DISTINCT resource>"], "ghosts": ["<front-controller / catch-all route>"]}"""


def say(tag, msg):
    sys.stderr.write(f"[{tag}] {msg}\n")


# -- suggester ---------------------------------------------------------------

class Suggester:
    name = "suggester"
    role = "suggester"
    profile = "a security generalist"
    focus = "general web/API security"
    proposes: tuple = ()          # executor specialists this manager may commission
    dissent = False               # the minority-report manager sets this: always opines, sees the board first

    def system(self) -> str:
        return (
            f"You are {self.name}, {self.profile} - a MANAGER on IRVIN's board. You run ONE lane and commission "
            f"verified work from the specialist executors in it; you never do the work yourself. Your lane: "
            f"{self.focus}.\n"
            "TWO RULES before you advise:\n"
            "1. STRICT - check ALL COMMISSIONS (below) before suggesting anything. Each entry is "
            "(executor, endpoint-family): findings, new surface. If the (executor, endpoint-family) you are "
            "about to propose is ALREADY IN THAT LIST - from any lane, any round - do NOT re-suggest it. "
            "The head will auto-decline a dead repeat; the thinner will gate a live one. An idle manager "
            "beats re-running work already done.\n"
            "2. COOPERATIVE - the commission log is shared across all lanes. Use it: if another lane confirmed "
            "a finding on a family your lane would naturally follow up on, that is an OPEN LEAD for you - pick "
            "it up. If another lane already saturated a family, move to uncovered ground instead.\n"
            "Every commission is a CONCRETE, DECIDABLE brief - a question a specialist can PROVE, not 'go look "
            "around'. Escalate confirmed leads; redirect around dead ends; SKIP when your lane has no "
            "evidence-backed work left - never commission busywork.\n"
            f"You may only commission these specialists: {', '.join(self.proposes) or '(none)'}.\n"
            'Reply with ONLY JSON: {"skip":false,"rationale":"<one line: what you are commissioning and why now, '
            'or why you stand down>","suggestions":[{"action":"<specialist>","target":"<url/host or empty>",'
            '"priority":1,"why":"<the brief: what this specialist must settle/prove>"}]}. '
            "priority 1=highest .. 5=lowest. Keep it to your 1-3 strongest commissions.")

    def _user(self, ctx, peers) -> str:
        parts = [
            f"ENGAGEMENT STATE:\n{ctx.landscape_digest()}",
            f"WHAT SPECIALISTS ACTUALLY DID (executor results only, most recent first):\n{ctx.executor_trail()}",
            f"YOUR COMMISSIONS SO FAR (your suggestions -> what came back):\n{ctx.advice_outcomes(self.name)}",
            f"ALL COMMISSIONS LOG (every lane, every round - check BEFORE advising):\n{ctx.all_commissions_render()}",
        ]
        if peers:
            parts.append("FELLOW MANAGERS COMMISSIONED THIS ROUND ALREADY (don't duplicate):\n" +
                         "\n".join(f"  {p.id} [{p.agent}] {p.summary} — {p.rationale}" for p in peers))
        parts += self._extra_parts(ctx)
        parts.append("Decide what to commission now. JSON only.")
        return "\n\n".join(parts)

    def _extra_parts(self, ctx) -> list:
        """Hook: extra prompt sections for a specific profile - default none. e.g. AuthProfile adds the
        deterministic auth-signal block; other profiles don't need it cluttering their prompt."""
        return []

    def suggest(self, ctx, provider, peers=None) -> dict:
        try:
            raw = provider.chat(self.system(), self._user(ctx, peers))
        except Exception as exc:  # noqa: BLE001 - a failing suggester just skips this round
            return {"skip": True, "rationale": f"provider error: {exc}", "suggestions": []}
        obj = extract_json(raw)
        sugg = [s for s in (obj.get("suggestions") or [])
                if isinstance(s, dict) and s.get("action") in self.proposes]
        return {"skip": bool(obj.get("skip")) or not sugg,
                "rationale": obj.get("rationale", ""), "suggestions": sugg}


# -- executor ----------------------------------------------------------------

class Executor:
    name = "executor"
    role = "executor"
    description = "does one unit of work and verifies it"
    objective = "Do your task, then verify your output."
    tools: set = set()
    cost = "med"        # low|med|high - typical expense per commission (requests/time); the planner/concluder
                         # weigh this against a lane's actual yield instead of treating every call as free
    max_steps = 12
    examples = ""       # concrete example calls, shown in the prompt so the model gets the invocations right
    # exactness over cost: re-test EVERY unconfirmed candidate, with a generous budget so multi-step proofs
    # (e.g. a full sqlmap dump, a cross-identity BOLA diff) can complete rather than time out.
    verify_steps = 10
    verify_paths_exist = False     # executors that GUESS/brute paths flip this on -> endpoints confirmed live

    def _say(self, msg):
        say(f"irvin:{self.name}", msg)

    def _enrich_step(self, ctx, step: dict) -> dict:
        """Hook: inject facts into the step before the prompt is built - default no-op. The auth executor
        uses this to resolve WHICH identity into a concrete login_url + credential placeholder, so the
        planner (an LLM) never needs to know anything about credentials - it just names the identity."""
        return step

    def _rewrite_call(self, ctx, name: str, args: dict) -> dict:
        """Hook: transform a tool call's args just BEFORE it is translated to argv and dispatched - default
        no-op (safe_args stays identical to the model-visible args, so this costs nothing for every other
        executor). The auth executor overrides this to substitute a stored-credential placeholder for the
        real secret, so the raw password never appears in the model's context, the provider's API payload, or
        the trail/debug log - only in the one argv actually sent to the runner."""
        return args

    def _to_argv(self, ctx, call: dict) -> tuple:
        """Returns (log_argv, real_argv): identical unless _rewrite_call changes something, in which case
        log_argv keeps the model-visible (safe) values and real_argv carries what actually gets dispatched."""
        log_argv = toolschema.to_argv(call["name"], call["args"])
        real_args = self._rewrite_call(ctx, call["name"], call["args"])
        real_argv = log_argv if real_args is call["args"] else toolschema.to_argv(call["name"], real_args)
        return log_argv, real_argv

    # -- vision: forward any image a tool produced to the model as a real picture, not base64 text ----------
    _MAX_IMAGES = 8                # per single tool call - a chain can hold several `screen`s; cap runaways
    _MAX_IMAGE_BYTES = 6_000_000   # skip an absurdly large capture rather than blow the request up

    def _take_images(self, out: str) -> tuple:
        """Pull any screenshot a tool reported (as a short `image_path`) OUT of the JSON envelope and hand it
        to the model as REAL vision. Delegates to the shared, ORDERED harvester so this matches logio and the
        model's contract: exactly one image per `screen`, in order, numbered - never an extra, out-of-order
        trailing state-shot that makes the agent read the wrong frame. See envelope.harvest_images."""
        return harvest_images(out, self._MAX_IMAGES, self._MAX_IMAGE_BYTES)

    def run(self, ctx, step, runner, provider) -> dict:
        step = self._enrich_step(ctx, step)
        system = (f"{_EXEC_BASE}\n\n{agentlog.NARRATE}\n## Your role: {self.name}\n{self.objective}\n\n"
                  f"## Tools you may call\n{', '.join(sorted(self.tools))}")
        if self.examples:
            system += f"\n\n## Example calls (adapt to the real target/params - illustrative, not literal)\n{self.examples}"
        tools_spec = toolschema.native_tools(sorted(self.tools))
        brief = step.get("brief") or step.get("why") or self.description
        parts = [f"YOUR TASK (from the planner): {brief}"]
        if step.get("args"):
            parts.append("ARGS: " + ", ".join(f"{k}={v}" for k, v in step["args"].items()))
        if step.get("context"):
            parts.append("RELEVANT CONTEXT (use this, don't re-discover it): " + step["context"])
        if step.get("avoid"):
            parts.append("DO NOT: " + step["avoid"])
        user = (f"ENGAGEMENT STATE:\n{ctx.landscape_digest()}\n\n" + "\n".join(parts) +
                "\n\nDo it now, verify, then emit the json handoff.")
        messages = [{"role": "user", "content": user}]
        final = ""
        for _ in range(self.max_steps):
            try:
                resp = provider.send(system, messages, tools_spec)
            except Exception as exc:  # noqa: BLE001
                say(f"irvin:{self.name}", f"provider error: {exc}")
                break
            text, calls = provider.parse(resp)
            messages += provider.assistant_msg(resp)
            if text.strip():
                final = text
                say(f"irvin:{self.name}", text.strip()[:300])          # stream reasoning live
            if not calls:
                break
            results = []
            for c in calls:
                log_argv, real_argv = self._to_argv(ctx, c)
                say(f"irvin:{self.name}", "> boxcutter " + " ".join(str(a) for a in log_argv))  # stream actions
                out = runner(real_argv, ctx=ctx, allowed=self.tools)
                self._absorb(ctx, log_argv, out)
                self._say("  <- " + agentlog.summarize(out))   # what the call actually returned, not just the command
                out, images = self._take_images(out)       # screenshots -> real vision blocks, not base64 text
                if images:
                    self._say(f"captured {len(images)} screenshot(s) for the model to see")
                results.append({"id": c["id"], "output": out, "images": images})
            messages += provider.tool_results(results)

        handoff = self._handoff(final)
        candidates = handoff.get("findings") or []
        verified, dropped = self._verify(ctx, candidates, runner, provider)
        handoff["findings"] = verified
        # tailored artifact verification: confirm reported paths/endpoints actually exist before they spread
        art = handoff.setdefault("artifacts", {})
        raw_eps = art.get("endpoints") or []
        kept_eps, dead_eps = self.verify_endpoints(ctx, raw_eps, runner, provider)
        art["endpoints"] = kept_eps
        if dead_eps:
            self._say(f"dropped {len(dead_eps)} ghost path(s) (catch-all/soft-404): {', '.join(dead_eps[:5])}"
                      + (" ..." if len(dead_eps) > 5 else ""))
        # deterministic panel routing: a discovered admin/management panel becomes a `panel` lead (deduped
        # against any the model already raised), so EXPOSURE is auto-commissioned on it and it can't be orphaned
        have = {(str(ld.get("cls", "")).lower(), ld.get("url") or ld.get("target", ""))
                for ld in (art.get("leads") or []) if isinstance(ld, dict)}
        for pl in _panel_leads(kept_eps):
            if (pl["cls"], pl["url"]) not in have:
                art.setdefault("leads", []).append(pl)
                have.add((pl["cls"], pl["url"]))
                self._say(f"raised panel lead (-> exposure) for reachable panel: {pl['url']}")
        handoff["verification"] = {"candidates": len(candidates), "verified": len(verified),
                                   "dropped": len(dropped), "dropped_titles": dropped,
                                   "endpoints_kept": len(kept_eps), "endpoints_dropped": len(dead_eps),
                                   "dead_paths": dead_eps, "method": "code-gate + independent re-test"}
        return handoff

    def verify_endpoints(self, ctx, endpoints, runner, provider):
        """Agentic existence check - the executor re-verifies its OWN discovered paths. Executors that
        GUESS/brute paths set verify_paths_exist; they run a focused agentic loop that fingerprints the host's
        catch-all/soft-404 behaviour and drops any path that is just the fallback (a ghost), because a 200 is
        not proof on a try_files/SPA host. The rest trust their endpoints. Returns (kept, dropped)."""
        eps = [u for u in (endpoints or []) if isinstance(u, str) and u.startswith(("http://", "https://"))]
        if not self.verify_paths_exist or not eps:
            return list(endpoints or []), []

        system = f"{_GHOST_VERIFY}\n\n## Tools you may call\n{', '.join(sorted(self.tools))}"
        tools_spec = toolschema.native_tools(sorted(self.tools))
        listing = "\n".join(f"  - {u}" for u in eps[:40])
        user = ("These are the paths you discovered on this host. Verify which TRULY EXIST vs which are just the "
                f"catch-all/soft-404 fallback (a 200 is not proof).\n\nCANDIDATES:\n{listing}\n\n"
                "Fingerprint the host, classify each candidate from its fetched response, then emit the json verdict.")
        messages = [{"role": "user", "content": user}]
        final = ""
        for _ in range(self.verify_steps):
            try:
                resp = provider.send(system, messages, tools_spec)
            except Exception as exc:  # noqa: BLE001 - on a verify error, keep the endpoints (don't lose surface)
                self._say(f"ghost-check provider error: {exc} - keeping endpoints unverified")
                return eps, []
            text, calls = provider.parse(resp)
            messages += provider.assistant_msg(resp)
            if text.strip():
                final = text
                self._say("ghost-check: " + text.strip()[:200])
            if not calls:
                break
            results = []
            for c in calls:
                log_argv, real_argv = self._to_argv(ctx, c)
                self._say("ghost-check> boxcutter " + " ".join(str(a) for a in log_argv))
                out = runner(real_argv, ctx=ctx, allowed=self.tools)
                self._absorb(ctx, log_argv, out)
                results.append({"id": c["id"], "output": out})
            messages += provider.tool_results(results)

        obj = extract_json(final)
        ghosts = {u for u in (obj.get("ghosts") or []) if isinstance(u, str)}
        # never drop the base root, whatever the agent says (its body legitimately equals the catch-all)
        ghosts = {u for u in ghosts if (urlsplit(u).path.strip("/") or urlsplit(u).query)}
        kept = [u for u in eps if u not in ghosts]
        dropped = [u for u in eps if u in ghosts]
        return kept, dropped

    # -- independent verification: each executor re-checks its OWN findings ----
    def _verify(self, ctx, candidates, runner, provider):
        """Confirm each candidate independently (code gate, then a fresh re-test with this executor's tools).
        Anything that cannot be reproduced is DROPPED. Returns (verified_findings, dropped_titles)."""
        verified, dropped = [], []
        for f in candidates:
            if not isinstance(f, dict) or not f.get("title"):
                continue
            if reproduce(ctx, f, runner):                      # deterministic code gate
                f["verified"], f["status"] = "code", "verified"
                verified.append(f)
                self._say(f"verified (code gate): {f.get('title')}")
                continue
            v = self._reverify(ctx, f, runner, provider)       # independent re-test with own tools
            if v.get("confirmed"):
                if v.get("evidence"):
                    f["evidence"] = str(v["evidence"])[:120]
                f["verified"], f["status"] = "re-test", "verified"
                verified.append(f)
                self._say(f"verified (independent re-test): {f.get('title')}")
            else:
                dropped.append(f.get("title") or f.get("url") or "?")
                self._say(f"DROPPED (could not reproduce): {f.get('title')} - {v.get('reason', '')[:80]}")
        return verified, dropped

    def _reverify(self, ctx, finding, runner, provider) -> dict:
        system = f"{_VERIFY_BASE}\n\n## Tools you may call\n{', '.join(sorted(self.tools))}"
        tools_spec = toolschema.native_tools(sorted(self.tools))
        user = ("CANDIDATE to verify (reproduce it from scratch, or declare it a false positive):\n"
                f"title: {finding.get('title')}\nurl: {finding.get('url')}\ncls: {finding.get('cls')}\n"
                f"claimed evidence: {finding.get('evidence')}\n\nRe-test now, then emit the json verdict.")
        messages = [{"role": "user", "content": user}]
        final = ""
        for _ in range(self.verify_steps):
            try:
                resp = provider.send(system, messages, tools_spec)
            except Exception as exc:  # noqa: BLE001 - a verify error means "not confirmed" (we drop on fail)
                return {"confirmed": False, "reason": f"verify provider error: {exc}"}
            text, calls = provider.parse(resp)
            messages += provider.assistant_msg(resp)
            if text.strip():
                final = text
                self._say("verify: " + text.strip()[:200])
            if not calls:
                break
            results = []
            for c in calls:
                log_argv, real_argv = self._to_argv(ctx, c)
                self._say("verify> boxcutter " + " ".join(str(a) for a in log_argv))
                out = runner(real_argv, ctx=ctx, allowed=self.tools)
                self._absorb(ctx, log_argv, out)
                results.append({"id": c["id"], "output": out})
            messages += provider.tool_results(results)
        obj = extract_json(final)
        return {"confirmed": bool(obj.get("confirmed")), "evidence": obj.get("evidence", ""),
                "reason": obj.get("reason", "")}

    # deterministic safety net: harvest URLs/secrets from every tool result even if the model under-reports
    def _absorb(self, ctx, argv, out):
        try:
            env = json.loads(out)
        except Exception:  # noqa: BLE001
            env = None
        tool = argv[0] if argv else ""
        data = env.get("data") if isinstance(env, dict) and isinstance(env.get("data"), list) else []
        # deterministic auth signal (ANY tool, not just discovery ones - http-request/fuzz are exactly where a
        # 401/403 from a now-stale session would show up). Not a trigger by itself: a legitimately-protected
        # endpoint also 401s/403s, so the auth suggester weighs this evidence, it doesn't act on it blindly.
        for d in data:
            if isinstance(d, dict) and isinstance(d.get("status"), int) and d["status"] in (401, 403):
                ctx.note_auth_signal(d["status"], d.get("url") or (argv[1] if len(argv) > 1 else ""))
        # Only DISCOVERY tools feed the surface. http-request/fuzz just echo the URL we asked for, so a 200
        # there is not evidence the path exists (on a catch-all host everything 200s) - existence is decided by
        # the agentic verify_endpoints at handoff, not by harvesting our own probes back into the landscape.
        if isinstance(env, dict) and env.get("success") and tool not in ("http-request", "fuzz"):
            urls = []
            for d in data:
                if isinstance(d, dict):
                    st = d.get("status")
                    if isinstance(st, int) and st in (400, 404, 410, 501):
                        continue                       # don't let dead paths pollute the surface
                    u = d.get("url")
                else:
                    u = d if isinstance(d, str) else None
                if isinstance(u, str) and u.startswith(("http://", "https://")):
                    urls.append(u)
            ctx.add_urls(urls)
        for tok in _JWT.findall(out):
            ctx.add_secret("jwt", tok, argv[1] if len(argv) > 1 else self.name)
            if not ctx.landscape["identities"]:
                ctx.add_identity("H", ["--header", f"Authorization: Bearer {tok}"], "harvested")
        for tok in _APIKEY.findall(out):
            ctx.add_secret("apikey", tok, argv[1] if len(argv) > 1 else self.name)

    def _handoff(self, final) -> dict:
        obj = extract_json(final)
        return {
            "findings": obj.get("findings") or [],
            "artifacts": obj.get("artifacts") or {},
            "verification": obj.get("verification") or {"validated": False, "notes": "no verification reported"},
        }

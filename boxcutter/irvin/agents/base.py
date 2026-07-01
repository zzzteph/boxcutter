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

import base64
import json
import os
import re
import sys
from urllib.parse import urlsplit

from ...tools import toolschema
from ..context import extract_json
from ..verify import reproduce

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_APIKEY = re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|secret)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9._-]{16,})")

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

End with ONE fenced ```json block and nothing after it:
{"findings":[{"severity":"High|Medium|Low","title":"...","url":"...","cls":"sqli|xss|bola|bfla|exposure|secret|lfi|rce|...","evidence":"<=100 chars verbatim, redacted"}],
 "artifacts":{"endpoints":["<url>"],"tokens":[{"header":"Authorization: Bearer ...","source":"<url>"}],"notes":["..."]},
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
_GHOST_VERIFY = """You are RE-VERIFYING which of YOUR discovered paths on one host ACTUALLY EXIST. Do NOT trust
an HTTP 200: many servers are a CATCH-ALL / soft-404 - Caddy `try_files {path} /index.php`, a single-page app,
or any framework that returns 200 + the SAME page for EVERY path, real or not. There a 200 is meaningless, and
a path exists ONLY if its response is MATERIALLY DIFFERENT from that catch-all page.

Work through it with http-request (reuse the strongest identity on every request):
1. FINGERPRINT the catch-all: request a path that cannot exist (e.g. /<random-string>, and a second different
   random path). Record the status, title, and body shape they return. If they come back 404/410/error, the
   host 404s honestly - then any non-error candidate is real.
2. CLASSIFY each candidate: fetch it and compare to the fingerprint. REAL = clearly different (a distinct
   title/structure/data, a real file, JSON, an error the catch-all never shows). GHOST = the catch-all page
   again (same shell, only dynamic bits differ) = the fallback, not a real resource. The site ROOT "/" is
   always REAL.
Be strict: when a candidate is indistinguishable from the catch-all page, it is a GHOST - drop it. Do not guess
from the URL; decide only from the fetched responses.

End with ONE fenced ```json block and nothing after it:
{"real": ["<url that truly exists>"], "ghosts": ["<url that is just the catch-all fallback>"]}"""


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
            "Read the engagement state and your specialists' prior results, then decide what to commission next: "
            "open new ground, ESCALATE a confirmed lead to the right specialist, REDIRECT around a dead end, or "
            "stand down. Every commission is a CONCRETE, DECIDABLE brief - a question a specialist can settle and "
            "PROVE (an endpoint to test, a lead to confirm, an artifact to retrieve), never 'go look around'. "
            "Build on what already happened and never re-commission work already answered. YOUR COMMISSIONS SO "
            "FAR (below) show exactly what came back from each one - if a commission ran and produced nothing (0 "
            "findings, 0 new surface), do NOT re-propose a near-identical brief on the same target without new "
            "evidence to justify it; move to different ground instead. Specialists return "
            "ONLY verified results, so ask for proof, not guesses. If there is no evidence-backed brief in your "
            "lane right now, SKIP - an idle manager beats busywork. Stay in your lane; other managers cover the "
            "rest.\n"
            f"You may only commission these specialists: {', '.join(self.proposes) or '(none)'}.\n"
            'Reply with ONLY JSON: {"skip":false,"rationale":"<one line: what you are commissioning and why now, '
            'or why you stand down>","suggestions":[{"action":"<specialist>","target":"<url/host or empty>",'
            '"priority":1,"why":"<the brief: what this specialist must settle/prove>"}]}. '
            "priority 1=highest .. 5=lowest. Keep it to your 1-3 strongest commissions.")

    def _user(self, ctx, peers) -> str:
        parts = [f"ENGAGEMENT STATE:\n{ctx.landscape_digest()}",
                 f"WHAT YOUR SPECIALISTS HAVE REPORTED (build on it):\n{ctx.recent_trail()}",
                 f"YOUR COMMISSIONS SO FAR (what you asked for -> what came back):\n{ctx.advice_outcomes(self.name)}"]
        if peers:
            parts.append("FELLOW MANAGERS HAVE ALREADY COMMISSIONED THIS ROUND (don't duplicate):\n" +
                         "\n".join(f"  {p.id} [{p.agent}] {p.summary} — {p.rationale}" for p in peers))
        dead = ctx.dead_commissions_render()
        if dead:
            parts.append("ALREADY ATTEMPTED - these ran and returned NOTHING; do NOT re-commission them without "
                         "new evidence (the head will auto-decline a repeat):\n" + dead)
        low = ctx.low_yield_render()
        if low:
            parts.append("LOW-YIELD LANES - these have run repeatedly with ZERO findings so far (even though "
                         "some still turn up new surface); weigh their cost before commissioning more of them:\n" + low)
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
    _MAX_IMAGES = 4                # per single tool call - a describe+screenshot pass yields one; cap runaways
    _MAX_IMAGE_BYTES = 6_000_000   # skip an absurdly large capture rather than blow the request up

    def _take_images(self, out: str) -> tuple:
        """A tool may emit a screenshot as a short `image_path` (browser-actions 'screenshot' does). Pull each
        one OUT of the JSON envelope, read the PNG from disk (the runner dispatches tools in-process, so the
        file is right here), and return (clean_text, images) - images being base64 blocks the provider sends
        as ACTUAL vision. The path is replaced with a short marker in the text so the model isn't told to
        re-fetch a file it can't reach, and a giant blob never rides in the text channel. General to any tool
        that reports image_path; today only the browser does. Best-effort: any parse/read failure just yields
        no images and the untouched text."""
        try:
            env = json.loads(out)
        except Exception:  # noqa: BLE001
            return out, []
        if not isinstance(env, dict) or not isinstance(env.get("data"), list):
            return out, []
        images: list = []

        def _harvest(node):
            if len(images) >= self._MAX_IMAGES:
                return
            if isinstance(node, dict):
                path = node.get("image_path")
                if isinstance(path, str) and path:
                    raw = None
                    try:
                        with open(path, "rb") as fh:
                            raw = fh.read()
                        os.unlink(path)                    # the capture is ephemeral - consume and drop it
                    except OSError:
                        raw = None
                    if raw and len(raw) <= self._MAX_IMAGE_BYTES:
                        images.append({"media_type": "image/png",
                                       "data": base64.b64encode(raw).decode("ascii")})
                        node["image_path"] = f"<screenshot captured ({len(raw)} bytes) - shown to you as an image>"
                    else:
                        node["image_path"] = "<screenshot unavailable>"
                for v in node.values():
                    _harvest(v)
            elif isinstance(node, list):
                for v in node:
                    _harvest(v)

        _harvest(env["data"])
        if not images:
            return out, []
        return json.dumps(env, ensure_ascii=False), images

    def run(self, ctx, step, runner, provider) -> dict:
        step = self._enrich_step(ctx, step)
        system = (f"{_EXEC_BASE}\n\n## Your role: {self.name}\n{self.objective}\n\n"
                  f"## Tools you may call\n{', '.join(sorted(self.tools))}")
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

"""Agentic executor base - each executor is an LLM working agent that drives boxcutter in its own loop.

ORCA (the planner) dispatches an executor with a TASK (shaped by the advisors); the executor then reasons,
calls boxcutter tools through the runner until it has done its job, and hands a structured result back to
the shared state. This mirrors bob's agents, but standalone and orchestrated by ORCA's queue. A
deterministic safety net runs on every tool result (harvest credentials, ingest discovered URLs) so the
surface and chains keep growing even when the model under-reports.
"""

from __future__ import annotations

import json
import re
import sys

from ..state import Finding, cls_from_fuzz_title

_BASE = """You are an EXECUTOR (a working agent) inside ORCA, an autonomous web/API bug-hunter. ORCA gave you
ONE task; do it thoroughly through boxcutter, then stop. You are not the planner - don't try to do other
roles' work; finish your task and report. Prove impact with non-destructive PoCs and quote verbatim
(redacted) evidence. Act ONLY through the run_boxcutter tool (boxcutter sub-commands; never PUT/PATCH/DELETE,
never docker/shell). Read each JSON envelope before the next call. Reuse the strongest IDENTITY on every
request. Be EXHAUSTIVE on the target you were given - cover every parameter/case before you stop.

End with ONE fenced ```json block and nothing after it:
{"findings":[{"severity":"High|Medium|Low","title":"...","url":"...","cls":"sqli|xss|bola|bfla|exposure|secret|ssti|lfi|rce|...","evidence":"<=100 chars verbatim, redacted","info":"..."}],
 "artifacts":{"tokens":[{"header":"Authorization: Bearer ...","source":"<url>"}],"endpoints":["<url>"],"notes":["..."]}}"""

# short per-tool hints for the executor's prompt (orca-local; no bob imports)
_TOOL_HINTS = {
    "httpx": "httpx <host> - liveness/title",
    "http-request": 'http-request <url> [-H "Name: Value"] [-D body] - GET, or POST when -D is given (no -X)',
    "katana-crawl": "katana-crawl <url> [--params|--js] - crawl for links/endpoints",
    "js-endpoints": "js-endpoints <js-url> --base-url <url> - extract API paths from JS",
    "dirsearch": "dirsearch <url> - brute directories under a base (not a file)",
    "dirb": "dirb <url> - directory brute-force with a DIFFERENT wordlist; run alongside dirsearch",
    "swagger-specs": "swagger-specs <host> - find OpenAPI spec URLs",
    "swagger-parser": "swagger-parser <spec> - parse a spec",
    "swagger-endpoints": "swagger-endpoints <spec> --fuzzable - list endpoints ({FUZZ}-marked)",
    "graphql-detect": "graphql-detect <host> - find GraphQL endpoints",
    "graphql-audit": "graphql-audit <url> - introspection/batching checks",
    "fuzz": 'fuzz <url> - injection battery (sqli/xss/ssti/lfi/ssrf/xxe/nosql); {FUZZ}/{NUMBERS} markers',
    "sqlmap": "sqlmap <url> [native flags like --dump --dbs --level 3] - confirm AND extract SQLi",
    "nuclei": 'nuclei <url> --opt-args "-tags exposure,misconfig,cve"',
    "git-extract": "git-extract <url>/ - dump an exposed .git",
    "scan-secrets": "scan-secrets <js-url> - find secrets (redacted)",
}

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_APIKEY = re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|secret)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9._-]{16,})")
_JSON_BLOCK = re.compile(r"```json\s*(\{.*\})\s*```", re.S)


class Executor:
    name = "executor"
    description = "does one unit of work"
    objective = "Do your task."
    tools: set = set()
    max_steps = 12

    # -- the agentic loop -----------------------------------------------------
    def run(self, state, task, runner, provider) -> None:
        system = (f"{_BASE}\n\n## Your role: {self.name}\n{self.objective}\n\n## Tools you may call\n"
                  + "\n".join(f"- {_TOOL_HINTS[t]}" for t in self.tools if t in _TOOL_HINTS))
        user = (f"ENGAGEMENT STATE:\n{state.digest()}\n\nYOUR TASK: {self._task_line(task)}\n\n"
                f"Do it now, then emit the json handoff.")
        messages = [{"role": "user", "content": user}]
        final = ""
        for _ in range(self.max_steps):
            try:
                resp = provider.send(system, messages)
            except Exception as exc:  # noqa: BLE001
                state.note(f"{self.name} provider error: {exc}")
                break
            text, calls = provider.parse(resp)
            messages += provider.assistant_msg(resp)
            if text.strip():
                final = text
                self.say(text.strip()[:300])          # stream reasoning live (like bob)
            if not calls:
                break
            results = []
            for c in calls:
                self.say("> boxcutter " + " ".join(str(a) for a in c["argv"]))   # stream each action live
                out = runner(c["argv"], ctx=state, allowed=self.tools)
                self._absorb(state, c["argv"], out)
                results.append({"id": c["id"], "output": out})
            messages += provider.tool_results(results)
        self._merge(state, final)

    def _task_line(self, task) -> str:
        if task.args:
            return f"{task.reason or self.description}  [target: " \
                   + ", ".join(f"{k}={v}" for k, v in task.args.items()) + "]"
        return task.reason or self.description

    def say(self, msg):
        sys.stderr.write(f"[orca:{self.name}] {msg}\n")

    # -- deterministic safety net on every tool result ------------------------
    def _absorb(self, state, argv, out):
        ok, kind, data = envelope(out)
        if not ok:
            return
        # ingest discovered URLs into the surface
        state.add_urls(urls_from(data))
        # ingest fuzz/sqlmap findings even if the model doesn't echo them
        if kind == "findings":
            for d in data:
                if isinstance(d, dict) and d.get("title"):
                    title = d["title"]
                    state.add_finding(Finding(str(d.get("severity", "info")).title(), title,
                                              d.get("url", argv[1] if len(argv) > 1 else ""),
                                              cls_from_fuzz_title(title) or _cls_hint(title),
                                              str(d.get("evidence", ""))[:120], d.get("info", ""), by=self.name))
        # harvest credentials -> secrets + identity
        for tok in _JWT.findall(out):
            state.add_secret("jwt", tok, argv[1] if len(argv) > 1 else self.name)
            if not any(k.startswith("H") for k in state.identities):
                state.add_identity("H", ["--header", f"Authorization: Bearer {tok}"], "harvested")
        for tok in _APIKEY.findall(out):
            state.add_secret("apikey", tok, argv[1] if len(argv) > 1 else self.name)

    # -- structured handoff -> state -----------------------------------------
    def _merge(self, state, final):
        obj = _extract(final)
        if not obj:
            return
        for f in obj.get("findings") or []:
            if not isinstance(f, dict):
                continue
            state.add_finding(Finding(str(f.get("severity", "info")).title(), f.get("title", ""),
                                      f.get("url", ""), str(f.get("cls", "")).lower(),
                                      str(f.get("evidence", ""))[:120], f.get("info", ""), by=self.name))
        art = obj.get("artifacts") or {}
        for i, tok in enumerate(art.get("tokens") or []):
            if tok.get("header"):
                state.add_identity(f"H{i + 1}", ["--header", tok["header"]], tok.get("source", self.name))
        state.add_urls(art.get("endpoints") or [])
        for n in art.get("notes") or []:
            state.note(n)


# -- module helpers -----------------------------------------------------------

def envelope(out):
    try:
        env = json.loads(out)
    except Exception:  # noqa: BLE001
        return False, "", []
    data = env.get("data")
    return bool(env.get("success")), env.get("kind", ""), data if isinstance(data, list) else []


def urls_from(data):
    out = []
    for d in data:
        u = d if isinstance(d, str) else (d.get("url") if isinstance(d, dict) else None)
        if isinstance(u, str) and u.startswith(("http://", "https://")):
            out.append(u)
    return out


def identity_args(state):
    if not state.identities:
        return []
    return list(state.identities.get(max(state.identities), []))


def _cls_hint(title):
    t = (title or "").lower()
    for c in ("sqli", "xss", "ssti", "lfi", "rce", "xxe", "nosql", "bola", "bfla", "secret", "exposure"):
        if c in t:
            return c
    return ""


def _extract(text):
    if not text:
        return None
    m = _JSON_BLOCK.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    dec = json.JSONDecoder()
    idx, best = text.find("{"), None
    while idx != -1:
        try:
            obj, end = dec.raw_decode(text, idx)
        except json.JSONDecodeError:
            idx = text.find("{", idx + 1)
            continue
        if isinstance(obj, dict) and ("findings" in obj or "artifacts" in obj):
            best = obj
        idx = text.find("{", max(end, idx + 1))
    return best

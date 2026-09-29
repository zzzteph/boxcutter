"""joseph-mcp - joseph's operator brain, EXTERNAL, driving boxcutter over MCP.

Where `joseph` runs IN the container and drives the tool registry in-process, `joseph-mcp` runs ANYWHERE and
drives a remote ``boxcutter mcp`` endpoint as its toolset. Same operator persona - think out loud, act, chain
findings toward the goal - but every action is an MCP ``tools/call`` instead of an in-process dispatch. The
tools it gets are exactly what the endpoint advertises: the deterministic registry (recon/crawl/scanners/
fuzzers/http-request) plus, when the endpoint exposes them, the sandboxed ``run_shell`` / ``run_python`` for the
operator's scripting edge (a raw curl, a bespoke fuzz loop, a chain).

    boxcutter ai joseph-mcp https://app.example.com \
        --mcp-url https://boxcutter-mcp.example.app/mcp/ --mcp-key $KEY \
        --provider claude-code --context "goal + endpoints + creds"

The LLM brain is a pluggable provider (provider.py) - anthropic / openai / litellm / ollama / claude-code -
so it needs a provider/API key (or the local Claude Code login). This is requests-only: the MCP client speaks
JSON-RPC over Streamable HTTP directly, so no `mcp` SDK is needed on the CLIENT side.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

import requests

from ..core.envelope import debug_print, output_result
from ..irvin.context import extract_json
from .provider import PROVIDERS, add_agent_args, make_provider, reset_usage, usage_cost

NAME = "joseph-mcp"
KIND = "findings"
HELP = ("Joseph over MCP: joseph's human-operator brain running EXTERNALLY, driving a remote `boxcutter mcp` "
        "endpoint as its toolset (deterministic tools + sandboxed run_shell/run_python). Thinks out loud and "
        "acts; produces a text report.")


_SYSTEM = (
    "You are JOSEPH, a HUMAN-OPERATOR security agent working THROUGH a remote boxcutter toolkit exposed over MCP. "
    "You are not a scanner walking a checklist - you are a pentester who reasons about the app, fires the right "
    "tool, reads the result, and reuses what you learn on the next move, toward a GOAL.\n\n"

    "YOUR TOOLS are the boxcutter tools this endpoint advertises. Among them:\n"
    "  - http-request - your scalpel: fetch/POST any URL with headers/body; read the exact response.\n"
    "  - recon/crawl/scanners (httpx, katana-crawl, nuclei, sqlmap, fuzz, js-endpoints, nmap, graphql-*, "
    "swagger-*, path-*, scan-secrets, ...) - use the one that fits the class you are hunting.\n"
    "  - run_shell / run_python (IF advertised) - run a raw command or a Python snippet in the container "
    "(sandboxed): a bespoke fuzz loop, a UNION-dump loop, a payload generator, an ORDER BY/column probe, a curl "
    "pipeline. Reach for these the moment the built-in tools don't fit the exact thing you want to try.\n\n"

    "THINK OUT LOUD every turn, BEFORE you act: OBSERVE (the exact value/status you saw) -> INTERPRET (what it "
    "means vs a baseline) -> TRACE (where a value flows) -> HYPOTHESIZE (a checkable claim + the observable you "
    "will check) -> PLAN (the next concrete checks) -> ACT (one tool call now). Ruling a thing OUT, with the "
    "reason, is as valuable as a finding.\n\n"

    "GOAL-DIRECTED. Your input is a MISSION BRIEF (goal + endpoints + how to authenticate), not just a URL. "
    "Start from the endpoints/creds it names. Confirm every lead by BEHAVIOUR: state the predicted observable "
    "and a control BEFORE you fire, then check the response. A confirmed bug is a HOP, not a stop - after each "
    "one, re-scan your inventory (creds, tokens, ids, endpoints) and compose the multi-hop chain toward the goal "
    "(e.g. SQLi -> dump the users table -> reuse creds -> reach the admin surface).\n\n"

    "SAFETY - boundary, not menu. Stay on the target and the API/backend hosts it itself calls. You may "
    "POST/PUT/DELETE within scope when a human tester would, with the least-intrusive benign proof; never be "
    "destructive (no data deletion, no DoS, only a throwaway test account).\n\n"

    "EVIDENCE GATE. Call a finding real only when its predicted observable passed and you have the replayable "
    "exchange. An unproven claim is a note, never a finding.\n\n"

    "FINISH: when done, reply with NO tool call and ONE fenced ```json block (nothing else) with EXACTLY these "
    "fields:\n"
    "```json\n"
    "{\n"
    '  "application": {"description":"<what the app is + purpose>","stack":"<framework/lang | server | CDN>",'
    '"api":"<REST/GraphQL/none>","auth":"<cookie/JWT/none>"},\n'
    '  "findings": [{"severity":"Critical|High|Medium|Low|Suggestion","title":"<short>","url":"<url>",'
    '"cls":"<class e.g. sqli/xss/idor>","summary":"<what+where+mechanism>","steps":["<repro step>"],'
    '"poc":"<runnable curl/python>","impact":"<what an attacker gains, tied to evidence>",'
    '"remediation":["<fix>"],"evidence":"<=280 chars redacted proof"}],\n'
    '  "investigation":"<the story: what you checked, ruled out, confirmed>",\n'
    '  "bottom_line":"<one sentence: the single biggest problem, or nothing obvious>"\n'
    "}\n```\n"
    "Only proven findings go in `findings`; redact secret values.")


def _cap(raw: str, max_chars: int = 60000) -> str:
    s = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    return s if len(s) <= max_chars else s[:max_chars] + f"\n...[+{len(s) - max_chars} chars truncated]"


class MCPClient:
    """A tiny MCP Streamable-HTTP client (requests + SSE), enough to list and call tools. Skips server
    notifications (the keepalive progress/log events) and returns the result whose id matches the request."""

    def __init__(self, url: str, key: str = "", timeout: int = 1200):
        self.url = url.rstrip()
        self.key = key
        self.timeout = timeout
        self._id = 0

    def _rpc(self, method: str, params: dict) -> dict:
        self._id += 1
        rid = self._id
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.key:
            headers["X-API-Key"] = self.key
            headers["Authorization"] = f"Bearer {self.key}"
        payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        r = requests.post(self.url, json=payload, headers=headers, stream=True, timeout=self.timeout)
        r.raise_for_status()
        ctype = r.headers.get("content-type", "")
        if "text/event-stream" in ctype:
            for raw in r.iter_lines(decode_unicode=True):
                if not raw or not raw.startswith("data: "):
                    continue
                try:
                    d = json.loads(raw[6:])
                except ValueError:
                    continue
                if d.get("id") == rid:                    # our result (skip keepalive notifications)
                    if "error" in d:
                        raise RuntimeError(json.dumps(d["error"]))
                    return d.get("result", {})
            return {}
        d = r.json()
        if "error" in d:
            raise RuntimeError(json.dumps(d["error"]))
        return d.get("result", {})

    def list_tools(self) -> list:
        res = self._rpc("tools/list", {})
        return [{"name": t["name"], "description": t.get("description", ""),
                 "schema": t.get("inputSchema", {"type": "object"})} for t in res.get("tools", [])]

    def call_tool(self, name: str, args: dict) -> str:
        res = self._rpc("tools/call", {"name": name, "arguments": args or {}})
        for c in res.get("content", []):
            if c.get("type") == "text":
                return c.get("text", "")
        sc = res.get("structuredContent")
        return json.dumps(sc) if sc is not None else json.dumps({"success": False, "error": "no content"})


def add_arguments(parser) -> None:
    parser.add_argument("target", nargs="?", default=None,
                        help="App root URL (optional; the goal/endpoints in --context can supply it)")
    parser.add_argument("--mcp-url", dest="mcp_url", default=os.environ.get("BOXCUTTER_MCP_URL"),
                        metavar="URL", help="The boxcutter MCP endpoint, e.g. https://host/mcp/ "
                                            "(env BOXCUTTER_MCP_URL)")
    parser.add_argument("--mcp-key", dest="mcp_key", default=os.environ.get("BOXCUTTER_MCP_API_KEY", ""),
                        metavar="KEY", help="MCP endpoint API key (env BOXCUTTER_MCP_API_KEY)")
    add_agent_args(parser, max_steps=60)


def _render_report(target: str, data: dict, findings: list) -> str:
    lines = [f"# joseph-mcp report - {target}", ""]
    app = data.get("application") if isinstance(data, dict) else None
    if isinstance(app, dict):
        lines += ["## Application", "",
                  f"- {app.get('description', '')}",
                  f"- stack: {app.get('stack', '')}", f"- api: {app.get('api', '')}",
                  f"- auth: {app.get('auth', '')}", ""]
    lines += [f"## Findings ({len(findings)})", ""]
    for f in findings:
        lines += [f"### [{f.get('severity', 'info')}] {f.get('title', '')}",
                  f"- {f.get('url', '')}  ({f.get('cls', '')})", "", f.get("summary", ""), ""]
        if f.get("impact"):
            lines += [f"**Impact:** {f['impact']}", ""]
        if f.get("poc"):
            lines += ["```", str(f["poc"]), "```", ""]
    if isinstance(data, dict):
        lines += ["## Investigation", "", data.get("investigation", ""), "",
                  "## Bottom line", "", data.get("bottom_line", ""), ""]
    return "\n".join(lines)


def run(args) -> int:
    context = (args.context or "").strip()
    target = (args.target or "").strip()
    urls = re.findall(r'https?://[^\s"\'<>)\]]+', context)
    if not target and urls:
        target = urls[0]
    if not args.mcp_url:
        sys.stderr.write("joseph-mcp: --mcp-url (or BOXCUTTER_MCP_URL) is required - the boxcutter MCP endpoint.\n")
        return 2
    if not target:
        output_result([], args.output, "joseph-mcp needs a target or a --context brief naming the endpoints")
        return 2

    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key and getattr(provider_cls, "requires_key", True):
        sys.stderr.write(f"joseph-mcp: an LLM is required - --api-key or {provider_cls.env} for --provider "
                         f"{args.provider}\n")
        return 2

    client = MCPClient(args.mcp_url, args.mcp_key)
    try:
        tools = client.list_tools()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"joseph-mcp: cannot reach the MCP endpoint {args.mcp_url}: {exc}\n")
        return 1
    if not tools:
        sys.stderr.write("joseph-mcp: the endpoint advertised no tools\n")
        return 1
    names = [t["name"] for t in tools]
    has_exec = "run_shell" in names or "run_python" in names
    debug_print(f"joseph-mcp :: {len(tools)} tools over MCP ({args.mcp_url})"
                + ("  [+ run_shell/run_python]" if has_exec else "  [no exec tools]"))

    reset_usage()
    provider = make_provider(args.provider, args.model, key, base_url=args.base_url,
                             reasoning=getattr(args, "reasoning", 0))
    provider.label = "joseph-mcp"
    provider.stream = not getattr(args, "quiet_reasoning", False)

    brief = ("MISSION BRIEF (goal + endpoints + how to authenticate):\n"
             f"{context or '(no context - infer the goal from the target)'}\n\n"
             f"TARGET: {target}\n"
             f"TOOLS AVAILABLE OVER MCP: {', '.join(names)}\n"
             "Think out loud (observe->interpret->trace->hypothesize->plan) then act. Begin.")
    messages = [{"role": "user", "content": brief}]

    final_text, count, step = "", {}, 0
    for step in range(max(1, args.max_steps)):
        try:
            resp = provider.send(_SYSTEM, messages, tools)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"joseph-mcp: provider error: {exc}\n")
            break
        text, calls = provider.parse(resp)
        messages += provider.assistant_msg(resp)
        if text.strip():
            final_text = text
        if not calls:
            if final_text.strip() and ("```json" in final_text or '"findings"' in final_text):
                break
            messages.append({"role": "user", "content": "Keep going - act through the tools. Narrate "
                             "observe->interpret->trace->hypothesize->plan first, then make one tool call."})
            continue
        results = []
        for c in calls:
            keyj = json.dumps([c["name"], c.get("args", {})], sort_keys=True, default=str)
            count[keyj] = count.get(keyj, 0) + 1
            if count[keyj] > 2:
                out = json.dumps({"success": False, "error": "already ran this exact call - reuse the result"})
            else:
                try:
                    out = client.call_tool(c["name"], c.get("args", {}))
                except Exception as exc:  # noqa: BLE001
                    out = json.dumps({"success": False, "error": f"{c['name']} over MCP failed: {exc}"})
            results.append({"id": c["id"], "output": _cap(out)})
        messages += provider.tool_results(results)

    data, findings = {}, []
    parsed = extract_json(final_text) if final_text else None
    if isinstance(parsed, dict):
        data = parsed
        findings = [f for f in (parsed.get("findings") or []) if isinstance(f, dict)]
        for f in findings:
            f["severity"] = str(f.get("severity", "info")).lower()

    cost, tot = usage_cost()
    report = _render_report(target, data, findings)
    sys.stderr.write(f"joseph-mcp :: {len(findings)} finding(s) over {step + 1} step(s)  "
                     f"{tot['total_tokens']:,} tokens  ~${cost:,.4f}\n")
    if not getattr(args, "table", False):
        debug_print(report + "\n")
    extra = {"target": target, "report": report, "steps": step + 1, "tokens": tot, "cost_usd": cost,
             "mcp_url": args.mcp_url, "tools": len(tools)}
    output_result(findings, args.output, extra=extra)
    if getattr(args, "table", False):
        sys.stdout.write("\n" + report + "\n")
    if getattr(args, "report", None):
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(report + "\n")
        except OSError as exc:
            sys.stderr.write(f"joseph-mcp: could not write report to {args.report}: {exc}\n")
    return 0

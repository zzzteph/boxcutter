"""LLM providers for irvin - requests-only HTTP wrappers (no SDKs).

Mirrors the provider contract irvin needs: `chat(system, user)` for the concluder/planner/reporter
(one-shot JSON or prose reasoning) and the send/parse/assistant_msg/tool_results tool-calling loop for any
executor that drives boxcutter through the model. Add a provider by implementing these and registering it
below.

`send(system, messages, tools)` takes NATIVE per-tool JSON schemas (see tools/toolschema.py - generated from
each boxcutter sub-command's own argparse, so a call the schema allows is one the CLI actually accepts) rather
than one generic "run_boxcutter(argv)" tool; `parse(resp)` returns each call as {id, name, args} - a tool name
plus its structured arguments - which the caller turns back into an argv via toolschema.to_argv().
"""

from __future__ import annotations

import json
import os
import time

import requests

_RETRY_STATUS = {429, 500, 502, 503, 504}


def _post(url, *, json, headers, timeout, attempts=4):
    """POST with bounded exponential backoff on 429/5xx and transient network errors."""
    for i in range(attempts):
        try:
            r = requests.post(url, json=json, headers=headers, timeout=timeout)
        except requests.RequestException:
            if i == attempts - 1:
                raise
            time.sleep(min(2 ** i, 8))
            continue
        if r.status_code in _RETRY_STATUS and i < attempts - 1:
            retry_after = r.headers.get("retry-after", "")
            time.sleep(float(retry_after) if retry_after.replace(".", "", 1).isdigit() else min(2 ** i, 8))
            continue
        r.raise_for_status()
        return r
    raise RuntimeError("unreachable")


class Anthropic:
    default_model, env = "claude-sonnet-4-6", "ANTHROPIC_API_KEY"
    _default_base, _base_env = "https://api.anthropic.com", "ANTHROPIC_BASE_URL"

    def __init__(self, model, key, base_url=None):
        self.model, self.key = model, key
        base = (base_url or os.environ.get(self._base_env) or self._default_base).rstrip("/")
        self.api = base + "/v1/messages"

    def _headers(self):
        return {"x-api-key": self.key, "anthropic-version": "2023-06-01", "content-type": "application/json"}

    def send(self, system, messages, tools):
        body = {"model": self.model, "max_tokens": 8192, "system": system, "messages": messages,
                "tools": [{"name": t["name"], "description": t["description"], "input_schema": t["schema"]} for t in tools]}
        return _post(self.api, json=body, timeout=180, headers=self._headers()).json()

    def parse(self, resp):
        text, calls = "", []
        for b in resp.get("content", []):
            if b.get("type") == "text":
                text += b["text"]
            elif b.get("type") == "tool_use":
                calls.append({"id": b["id"], "name": b["name"], "args": b.get("input") or {}})
        return text, calls

    def assistant_msg(self, resp):
        return [{"role": "assistant", "content": resp.get("content", [])}]

    def tool_results(self, results):
        content = []
        for r in results:
            imgs = r.get("images") or []
            if imgs:
                # Anthropic tool_result content may be a block list: the text plus each screenshot as a real
                # image the model actually sees (base64 source), not an unreadable blob in the text.
                blocks = [{"type": "text", "text": r["output"]}]
                blocks += [{"type": "image", "source": {"type": "base64",
                            "media_type": im.get("media_type", "image/png"), "data": im["data"]}} for im in imgs]
                content.append({"type": "tool_result", "tool_use_id": r["id"], "content": blocks})
            else:
                content.append({"type": "tool_result", "tool_use_id": r["id"], "content": r["output"]})
        return [{"role": "user", "content": content}]

    def chat(self, system, user, max_tokens=None):
        # Anthropic requires max_tokens; None means "use a generous budget" (no artificial cap).
        body = {"model": self.model, "max_tokens": max_tokens or 8192, "system": system,
                "messages": [{"role": "user", "content": user}]}
        r = _post(self.api, json=body, timeout=120, headers=self._headers())
        return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")


class OpenAI:
    default_model, env = "gpt-4o", "OPENAI_API_KEY"
    _default_base, _base_env = "https://api.openai.com", "OPENAI_BASE_URL"

    def __init__(self, model, key, base_url=None):
        self.model, self.key = model, key
        base = (base_url or os.environ.get(self._base_env) or self._default_base).rstrip("/")
        self.api = base + ("/chat/completions" if base.endswith("/v1") else "/v1/chat/completions")

    def _headers(self):
        return {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}

    def send(self, system, messages, tools):
        body = {"model": self.model, "messages": [{"role": "system", "content": system}] + messages,
                "tools": [{"type": "function", "function": {
                    "name": t["name"], "description": t["description"], "parameters": t["schema"]}} for t in tools]}
        return _post(self.api, json=body, timeout=180, headers=self._headers()).json()

    def parse(self, resp):
        msg = resp["choices"][0]["message"]
        calls = []
        for c in (msg.get("tool_calls") or []):
            try:
                args = json.loads(c["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append({"id": c["id"], "name": c["function"]["name"], "args": args})
        return msg.get("content") or "", calls

    def assistant_msg(self, resp):
        return [resp["choices"][0]["message"]]

    def tool_results(self, results):
        # Every tool_call_id must be answered by a `tool` message FIRST; the OpenAI tool role only carries
        # text, so any screenshots follow in a single `user` message with image_url blocks (a data: URL each)
        # - which multimodal models (gpt-5.1 et al.) read as real vision.
        msgs = [{"role": "tool", "tool_call_id": r["id"], "content": r["output"]} for r in results]
        blocks = []
        for r in results:
            for im in (r.get("images") or []):
                blocks.append({"type": "image_url", "image_url": {
                    "url": f"data:{im.get('media_type', 'image/png')};base64,{im['data']}"}})
        if blocks:
            msgs.append({"role": "user", "content": [
                {"type": "text", "text": "Screenshot(s) from the tool call(s) above:"}] + blocks})
        return msgs

    def chat(self, system, user, max_tokens=None):
        # OpenAI/LiteLLM: max_tokens is optional - omit it so the model uses its full budget (no cap).
        body = {"model": self.model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if max_tokens:
            body["max_tokens"] = max_tokens
        r = _post(self.api, json=body, timeout=120, headers=self._headers())
        return r.json()["choices"][0]["message"].get("content") or ""


class LiteLLM(OpenAI):
    """LiteLLM gateway - OpenAI-compatible wire format. Point with --base-url / LITELLM_BASE_URL."""
    default_model, env = "gpt-4o", "LITELLM_API_KEY"
    _default_base, _base_env = "http://localhost:4000", "LITELLM_BASE_URL"


PROVIDERS = {"anthropic": Anthropic, "openai": OpenAI, "litellm": LiteLLM}


def add_ai_provider_args(parser) -> None:
    """The shared LLM flags every `ai` agent (logio, prawlio, irvin) takes - defined ONCE here so the
    agents don't each redeclare them. NOTE: these live on each agent's OWN parser, not on the `ai` group: a
    true argparse group-level flag is clobbered by the subparser's default, and the bare-name sugar
    (`boxcutter logio ...`) puts flags AFTER the agent name - so a shared adder, not a group argument, is the
    correct way to share them."""
    parser.add_argument("--provider", default="anthropic", choices=list(PROVIDERS),
                        help="LLM provider (default anthropic; 'litellm' fronts any provider via your gateway)")
    parser.add_argument("--model", default=None, help="Model id (default: the provider's default)")
    parser.add_argument("--api-key", dest="api_key", default=None,
                        help="LLM API key (or set the provider's env var, e.g. ANTHROPIC_API_KEY)")
    # The LLM endpoint (a LiteLLM/OpenAI gateway or a direct API base). Named --llm-proxy-url, not --base-url,
    # so it can't be confused with the TARGET's base URL; the internal attribute stays `base_url` (the SDK term).
    parser.add_argument("--llm-proxy-url", dest="base_url", default=None, metavar="URL",
                        help="LLM endpoint / gateway URL (e.g. a LiteLLM or OpenAI-compatible proxy)")


def add_agent_args(parser, *, max_steps: int, context: bool = True) -> None:
    """The UNIFIED argument surface every standalone `ai` agent shares, so the CLI is consistent across agents:
    a free-text --context briefing, the LLM provider flags (add_ai_provider_args), the step cap (--max-steps),
    an optional --report file, request --header(s), and the common output flags (--output/--jsonl/--debug/
    --table). The per-agent --max-steps DEFAULT is passed in; the flag DEFINITIONS stay identical everywhere.
    Call it AFTER the agent's positional target and its own agent-specific flags."""
    from ..core.args import add_common_args, add_header_arg
    if context:
        parser.add_argument("--context", default="", metavar="TEXT",
                            help="Free-text briefing: scope and any auth header/cookie/creds to send (parsed by the LLM)")
    add_ai_provider_args(parser)
    parser.add_argument("--max-steps", dest="max_steps", type=int, default=max_steps,
                        help="Hard cap on agent steps (the agent usually stops earlier when it is done)")
    parser.add_argument("--report", default=None, metavar="FILE",
                        help="Also write the human-readable markdown report to FILE")
    add_header_arg(parser)
    add_common_args(parser)

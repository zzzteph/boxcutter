"""LLM providers — requests-only HTTP wrappers (no SDKs).

Each provider offers two calls:
  * send/parse/assistant_msg/tool_results — the tool-calling loop an agent drives
  * chat — a one-shot completion (no tools) for judgment helpers (classify, verify, correlate)

Add a provider by implementing those five methods and registering it in PROVIDERS.
"""

from __future__ import annotations

import json
import os
import time

import requests

_RETRY_STATUS = {429, 500, 502, 503, 504}


def _post(url, *, json, headers, timeout, attempts=4):
    """POST with bounded exponential backoff on 429/5xx and transient network errors.

    A single transient hiccup must not abort an agent mid-hunt, so we retry instead of letting the
    exception propagate straight out of send()/chat().
    """
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


# The single tool every agent drives. The model passes argv tokens; the Runner executes them.
TOOLS = [{
    "name": "run_boxcutter",
    "description": (
        "Run ONE boxcutter sub-command or workflow and get its JSON envelope "
        "{success,kind,data,error}. Pass argv as a token list, e.g. "
        '["fuzz","https://x/?id=1"], ["dirsearch","https://x/admin"], '
        '["git-extract","https://x/panel/"], ["http-request","https://x/api","--header",'
        '"Authorization: Bearer T"]. Only boxcutter sub-commands; never PUT/PATCH/DELETE. Do NOT '
        "include docker/podman/run/--rm/the image — just the boxcutter tool name and its args."
    ),
    "schema": {"type": "object",
               "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
               "required": ["argv"]},
}]


class Anthropic:
    default_model, env = "claude-sonnet-4-6", "ANTHROPIC_API_KEY"
    _default_base, _base_env = "https://api.anthropic.com", "ANTHROPIC_BASE_URL"

    def __init__(self, model, key, base_url=None):
        self.model, self.key = model, key
        base = (base_url or os.environ.get(self._base_env) or self._default_base).rstrip("/")
        self.api = base + "/v1/messages"

    def _headers(self):
        return {"x-api-key": self.key, "anthropic-version": "2023-06-01", "content-type": "application/json"}

    def send(self, system, messages):
        body = {"model": self.model, "max_tokens": 4096, "system": system, "messages": messages,
                "tools": [{"name": t["name"], "description": t["description"], "input_schema": t["schema"]} for t in TOOLS]}
        r = _post(self.api, json=body, timeout=180, headers=self._headers())
        return r.json()

    def parse(self, resp):
        text, calls = "", []
        for b in resp.get("content", []):
            if b.get("type") == "text":
                text += b["text"]
            elif b.get("type") == "tool_use":
                calls.append({"id": b["id"], "argv": (b.get("input") or {}).get("argv", [])})
        return text, calls

    def assistant_msg(self, resp):
        return [{"role": "assistant", "content": resp.get("content", [])}]

    def tool_results(self, results):
        return [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": r["id"], "content": r["output"]} for r in results]}]

    def chat(self, system, user, max_tokens=1500):
        body = {"model": self.model, "max_tokens": max_tokens, "system": system,
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

    def send(self, system, messages):
        body = {"model": self.model, "messages": [{"role": "system", "content": system}] + messages,
                "tools": [{"type": "function", "function": {
                    "name": t["name"], "description": t["description"], "parameters": t["schema"]}} for t in TOOLS]}
        r = _post(self.api, json=body, timeout=180, headers=self._headers())
        return r.json()

    def parse(self, resp):
        msg = resp["choices"][0]["message"]
        calls = []
        for c in (msg.get("tool_calls") or []):
            try:
                argv = json.loads(c["function"].get("arguments") or "{}").get("argv", [])
            except json.JSONDecodeError:
                argv = []
            calls.append({"id": c["id"], "argv": argv})
        return msg.get("content") or "", calls

    def assistant_msg(self, resp):
        return [resp["choices"][0]["message"]]

    def tool_results(self, results):
        return [{"role": "tool", "tool_call_id": r["id"], "content": r["output"]} for r in results]

    def chat(self, system, user, max_tokens=1500):
        body = {"model": self.model, "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        r = _post(self.api, json=body, timeout=120, headers=self._headers())
        return r.json()["choices"][0]["message"].get("content") or ""


class LiteLLM(OpenAI):
    """LiteLLM gateway - OpenAI-compatible, so it reuses OpenAI's wire format and __init__.

    Point it with --base-url or LITELLM_BASE_URL (default http://localhost:4000) and a key via --api-key
    or LITELLM_API_KEY; pick the routed model with --model. Fronts any provider through one gateway.
    """
    default_model, env = "gpt-4o", "LITELLM_API_KEY"
    _default_base, _base_env = "http://localhost:4000", "LITELLM_BASE_URL"


PROVIDERS = {"anthropic": Anthropic, "openai": OpenAI, "litellm": LiteLLM}

"""LLM providers for orca - requests-only HTTP wrappers (no SDKs), standalone (no bob imports).

Mirrors the provider contract orca needs: `chat(system, user)` for the planner/reporter (one-shot JSON
or prose reasoning) and the send/parse/assistant_msg/tool_results tool-calling loop for any executor that
wants to drive boxcutter through the model. Add a provider by implementing these and registering it below.
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


# The single tool an executor drives if it wants the model to choose boxcutter calls directly.
TOOLS = [{
    "name": "run_boxcutter",
    "description": (
        "Run ONE boxcutter sub-command and get its JSON envelope {success,kind,data,error}. Pass argv as "
        'a token list, e.g. ["fuzz","https://x/?id=1"], ["http-request","https://x/api","--header",'
        '"Authorization: Bearer T"]. Only boxcutter sub-commands; no docker/podman, no PUT/PATCH/DELETE.'
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
        body = {"model": self.model, "max_tokens": 8192, "system": system, "messages": messages,
                "tools": [{"name": t["name"], "description": t["description"], "input_schema": t["schema"]} for t in TOOLS]}
        return _post(self.api, json=body, timeout=180, headers=self._headers()).json()

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

    def send(self, system, messages):
        body = {"model": self.model, "messages": [{"role": "system", "content": system}] + messages,
                "tools": [{"type": "function", "function": {
                    "name": t["name"], "description": t["description"], "parameters": t["schema"]}} for t in TOOLS]}
        return _post(self.api, json=body, timeout=180, headers=self._headers()).json()

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

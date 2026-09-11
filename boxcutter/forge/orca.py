"""Pluggable ORCA backends for boxcutter-forge.

The forge conductor is deterministic: it maps assets, runs boxcutter workflows
locally, captures the HTTP exchanges, and reports. The single point of LLM
JUDGMENT (the "orca") - rank the surface, pick which workflow to run, author a hypothesis and
its predicted observable, grade a captured exchange, chain findings - goes through
ONE tiny interface, so the conductor never cares which model or agent answers:

    orca.decide(task, context) -> dict        # JSON in, JSON out

The task names and the JSON shapes mirror vera's action vocabulary (build_plan,
add_hypothesis, validate_hypothesis, load_skill; see docs/vera-design.md), so the
forge speaks the same syntax vera does - the difference is only WHO answers.

Which backend answers is chosen exactly the way security-forge's resolve_backend
does (precedence high -> low):

  * --mock                         deterministic, offline, no network       [MockJudge]
  * --provider litellm|anthropic|openai|ollama  (or --api-key / --llm-proxy-url)
                                   the native provider layer, boxcutter/ai/provider.py;
                                   litellm fronts any gateway                [ProviderJudge]
  * --orca-cmd "<template>"       that exact console agent CLI, {model}/{prompt}   [CliJudge]
  * (no backend args)              a console agent CLI already on PATH, tried in
                                   order: claude, deepseek, codex - one-shot, JSON  [CliJudge]
  * (nothing available)            falls back to MockJudge with a printed reason

None of these route to the internal bob/caleb/travis agents.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess

# Console agent CLIs tried, in this order, when no backend is specified. The value
# is (binary, output-format) - the command line itself is assembled in
# `_console_template` so the model id is baked in only when one is given (a bare
# `--model` with an empty value would otherwise break the child CLI).
_CONSOLE_AGENTS = [
    ("claude", "text"),
    ("deepseek", "text"),
    ("codex", "jsonl"),
]

_ORCA_SYSTEM = (
    "You are the judgment step of an automated security audit. You are given a TASK "
    "and a JSON CONTEXT of what the deterministic tools already observed. Reason, then "
    "reply with ONE JSON value that matches the task's requested schema and NOTHING else "
    "- no prose, no markdown fences."
)


def _console_template(binary: str, model: str) -> str:
    """The one-shot command template for a detected console agent, with `{prompt}`
    left for substitution and the model baked in (only when supplied)."""
    m = f" --model {shlex.quote(model)}" if model else ""
    if binary == "claude":
        # print mode, plain text out; no tools are needed for a judgment call
        return f"claude -p {{prompt}}{m}"
    if binary == "codex":
        return f"codex exec{m} --dangerously-bypass-approvals-and-sandbox {{prompt}}"
    if binary == "deepseek":
        # best-effort default; override with --orca-cmd if this CLI differs
        return f"deepseek{m} {{prompt}}"
    return f"{binary}{m} {{prompt}}"


def _detect_console_agent(model: str):
    for binary, output in _CONSOLE_AGENTS:
        if shutil.which(binary):
            return _console_template(binary, model), output, binary
    return None


def _extract_json(text: str):
    """Pull the JSON value out of a model/CLI reply. Tolerates markdown fences, a
    jsonl/stream-json transcript (scans lines), and leading/trailing prose. Returns
    the parsed object/list, or ``{"_parse_error": True, "raw": ...}`` on failure."""
    if not isinstance(text, str) or not text.strip():
        return {"_parse_error": True, "raw": ""}
    s = text.strip()
    # whole-string, then fence-stripped
    for cand in (s, re.sub(r"^```(?:json)?|```$", "", s, flags=re.M).strip()):
        try:
            return json.loads(cand)
        except (ValueError, TypeError):
            pass
    # jsonl / stream-json: try each line, keep the last object that parses
    last = None
    for line in s.splitlines():
        line = line.strip()
        if line[:1] in "{[":
            try:
                last = json.loads(line)
            except (ValueError, TypeError):
                pass
    if last is not None:
        return last
    # greedy: the largest balanced {...} or [...] block anywhere in the text
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i, j = s.find(open_c), s.rfind(close_c)
        if 0 <= i < j:
            try:
                return json.loads(s[i:j + 1])
            except (ValueError, TypeError):
                pass
    return {"_parse_error": True, "raw": s[:500]}


def _prompt(task: str, context: dict, schema_hint: str) -> str:
    parts = [f"TASK: {task}"]
    if schema_hint:
        parts.append(f"REPLY SCHEMA: {schema_hint}")
    parts.append("CONTEXT:")
    parts.append(json.dumps(context, ensure_ascii=False, indent=2, default=str))
    return "\n".join(parts)


class Orca:
    """One judgment call (an "orca"). Subclasses implement how the reply is produced."""

    name = "base"

    def decide(self, task: str, context: dict, *, schema_hint: str = "") -> dict:
        raise NotImplementedError


class ProviderOrca(Orca):
    """Answers via boxcutter's own provider layer (anthropic/openai/litellm/ollama).
    This is the 'use litellm or a named API' path - litellm fronts any gateway."""

    def __init__(self, provider) -> None:
        self.provider = provider
        self.name = f"provider:{getattr(provider, 'name', '') or type(provider).__name__.lower()}"

    def decide(self, task: str, context: dict, *, schema_hint: str = "") -> dict:
        text = self.provider.chat(_ORCA_SYSTEM, _prompt(task, context, schema_hint))
        return _extract_json(text if isinstance(text, str) else str(text))


class CliOrca(Orca):
    """Answers by running a console agent CLI once with the judgment prompt and
    reading its stdout as JSON. `template` is a shlex command with `{prompt}` and
    optional `{model}` placeholders, substituted token-wise (the prompt stays ONE
    argv element - no shell) exactly like security-forge's cli-adapter backend."""

    def __init__(self, template: str, model: str = "", output: str = "text",
                 name: str = "cli", timeout: int = 180) -> None:
        self.template = template
        self.model = model or ""
        self.output = (output or "text").lower()
        self.name = name
        self.timeout = timeout

    def build_command(self, prompt: str) -> list[str]:
        toks = shlex.split(self.template, posix=(os.name != "nt"))
        if not toks:
            raise ValueError("forge: empty --orca-cmd template")
        out, saw_prompt = [], False
        for t in toks:
            t = t.replace("{model}", self.model)
            if "{prompt}" in t:
                saw_prompt = True
                t = t.replace("{prompt}", prompt)
            out.append(t)
        if not saw_prompt:
            out.append(prompt)
        return out

    def decide(self, task: str, context: dict, *, schema_hint: str = "") -> dict:
        prompt = _ORCA_SYSTEM + "\n\n" + _prompt(task, context, schema_hint)
        try:
            proc = subprocess.run(self.build_command(prompt), capture_output=True,
                                  text=True, timeout=self.timeout)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"_error": f"{self.name} judge failed: {exc}"}
        return _extract_json(proc.stdout or "")


class MockOrca(Orca):
    """Deterministic, offline judge so `forge ... --mock` runs end to end with no
    network or CLI. Passes findings through unchanged and echoes the task."""

    name = "mock"

    def __init__(self, reason: str = "") -> None:
        self.reason = reason

    def decide(self, task: str, context: dict, *, schema_hint: str = "") -> dict:
        if "findings" in context:
            return {"keep": context["findings"], "verdict": "open_proof_gap", "tier": "mock"}
        if "assets" in context:
            return {"ranked": context["assets"]}
        return {"mock": True, "task": task}


def _provider_requested(args) -> bool:
    return bool(getattr(args, "provider", None)
                or getattr(args, "api_key", None)
                or getattr(args, "base_url", None))


def resolve_orca(args) -> Orca:
    """Pick the judge backend. Precedence mirrors security-forge's resolve_backend:
    --mock > explicit provider/API > explicit --orca-cmd > a detected console agent
    (claude/deepseek/codex) > MockJudge fallback."""
    if getattr(args, "mock", False):
        return MockOrca()

    if _provider_requested(args):
        from ..ai.provider import make_provider  # lazy: keep the lean engine clean
        prov = make_provider(getattr(args, "provider", None) or "litellm",
                             getattr(args, "model", None),
                             getattr(args, "api_key", None),
                             getattr(args, "base_url", None))
        return ProviderOrca(prov)

    model = getattr(args, "model", None) or ""
    if getattr(args, "orca_cmd", None):
        return CliOrca(args.orca_cmd, model, getattr(args, "orca_output", "text"),
                        name="orca-cmd")

    detected = _detect_console_agent(model)
    if detected:
        template, output, binary = detected
        return CliOrca(template, model, output, name=binary)

    return MockOrca(reason="no console agent (claude/deepseek/codex) on PATH and no "
                            "--provider/--orca-cmd given; using the offline mock judge")


def add_orca_args(parser) -> None:
    """The forge's orca-backend flags. `--provider` defaults to None (not anthropic)
    so 'no backend args' resolves to a console agent, per the spec, not to a provider."""
    from ..ai.provider import PROVIDERS
    parser.add_argument("--provider", default=None, choices=list(PROVIDERS),
                        help="Answer judgment calls with this provider directly "
                             "(litellm fronts any gateway) instead of a console agent CLI.")
    parser.add_argument("--model", default=None,
                        help="Model id: fills {model} in a console/--orca-cmd template, "
                             "or the provider's model.")
    parser.add_argument("--api-key", dest="api_key", default=None,
                        help="Provider API key (else the provider's env var).")
    parser.add_argument("--llm-proxy-url", dest="base_url", default=None, metavar="URL",
                        help="LLM endpoint / gateway URL (a LiteLLM or OpenAI-compatible proxy).")
    parser.add_argument("--orca-cmd", dest="orca_cmd", default=None, metavar="TEMPLATE",
                        help='Console agent command template with {model}/{prompt}, e.g. '
                             '"codex exec --model {model} {prompt}".')
    parser.add_argument("--orca-output", dest="orca_output", default="text",
                        choices=["text", "jsonl", "stream-json"],
                        help="How to read the --orca-cmd agent's stdout (default text).")
    parser.add_argument("--mock", action="store_true",
                        help="Use the deterministic offline judge (no network, no CLI).")

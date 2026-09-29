"""``boxcutter mcp`` - expose boxcutter's deterministic tool registry as a fully MCP-compliant server, so any
agentic client (Claude Desktop, an IDE agent, a custom LLM app, another orchestrator) can drive the toolkit
over the Model Context Protocol.

Two transports, one server:

    boxcutter mcp                              # stdio (default) - for clients that SPAWN boxcutter as a subprocess
    boxcutter mcp --http --port 9000           # Streamable HTTP - a NETWORKED endpoint agents connect to
    boxcutter mcp --http --api-key $SECRET     # ...with an optional shared-secret gate

On the HTTP transport an optional API key (``--api-key`` or ``BOXCUTTER_MCP_API_KEY``) is required as either
``Authorization: Bearer <key>`` or ``X-API-Key: <key>``; without one the endpoint is open (localhost-friendly).

Long tool calls are synchronous (the request stays open for the whole scan), so behind a proxy with a read
timeout - Cloudflare cuts at ~100s (524), nginx at 60s - a slow tool (nuclei/katana/fuzz/sqlmap) would be
severed mid-run. The server emits a keepalive notification every ``BOXCUTTER_MCP_KEEPALIVE`` seconds (default
20; 0 disables) on the request's own stream so bytes keep flowing and the connection is never timed out.

WHAT IS EXPOSED: the deterministic tools (recon, crawl, scanners, fuzzers, http-request, ...) plus two raw exec
tools, ``run_shell`` and ``run_python``, so an agent has the operator's scripting edge (a raw curl, a bespoke
fuzz loop, a chain) alongside the structured tools. The exec tools are ON by default and SANDBOXED - a
dedicated working dir as cwd, dropped to a low-privilege user when the server is root, so a script can't delete
files it doesn't own; turn them off with ``BOXCUTTER_MCP_NO_EXEC=1`` / ``--no-exec``. The LLM-driven ``ai``
agents are deliberately NOT deployable here - they need a provider/API key and per-run preconfiguration, which
a stateless MCP endpoint can't carry. Each deterministic tool's name, description and JSON-Schema are derived
straight from the tool's own argparse via ``tools.toolschema``, so the advertised contract can never drift from
what the CLI actually accepts.

boxcutter's vuln-class PLAYBOOKS (``ai/skills/*.md`` - deep methodology per class) are exposed too, so any
client gets the same knowledge boxcutter's own agents use: a read-only ``load_skill`` TOOL (an autonomous agent
pulls a playbook by name) AND MCP PROMPTS (a prompt-aware client lists/fetches them). Reference data - they
run nothing.

The ``mcp`` SDK is an OPTIONAL dependency, kept out of the lean engine exactly like the web server's deps.
Install it with::

    pip install -r requirements.txt      # then: boxcutter mcp

Full generated documentation of every exposed tool: ``boxcutter mcp --print-docs`` (or see docs/MCP_TOOLS.md).
"""
from __future__ import annotations

import argparse
import contextlib
import functools
import hmac
import json
import os
import subprocess
import sys
import tempfile

from .ai import skills
from .core import capability
from .tools import toolschema
from .tools.registry import TOOLS

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # repo root: has boxcutter.py, server/
_BOXCUTTER = os.path.join(_ROOT, "boxcutter.py")

SERVER_NAME = "boxcutter"

# Keepalive for long tool calls. An MCP tool call is synchronous - the HTTP request stays open for the tool's
# whole runtime - so a scan that outlives a proxy's read timeout (Cloudflare's edge cuts at ~100s with a 524,
# nginx defaults to 60s) gets severed mid-run. While a tool runs we emit a progress + log notification every
# KEEPALIVE_SECS on THIS request's stream, so bytes keep flowing and the proxy never times the connection out.
# Kept well under 100s; set BOXCUTTER_MCP_KEEPALIVE=0 to disable. (Behind Cloudflare also raise/relax the edge
# timeout or grey-cloud the host for tools that can run for many minutes.)
KEEPALIVE_SECS = float(os.environ.get("BOXCUTTER_MCP_KEEPALIVE", "20") or 0)

# Tools that send active-attack traffic or can CHANGE server state. Everything else is recon/read-only. These
# drive the MCP tool ANNOTATIONS (hints an agent can use to decide what needs confirmation) - conservative on
# purpose: when unsure, a tool is flagged rather than left looking safe. Annotations are hints, not a guard;
# the real scope/authorisation boundary is the operator running boxcutter against an in-scope target.
_MUTATING = {
    "http-request", "mass-assign", "browser-actions", "browser-login",
    "sqlmap", "fuzz", "blind-oracle", "zap-scan-url", "zap-scan-full", "zap-scan-openapi",
}
# Active but non-mutating (they probe hard but only read): still worth marking not-read-only so an agent knows
# they generate real traffic against the target.
_ACTIVE_READ = {
    "nuclei", "dirb", "dirsearch", "path-fuzz", "path-bust", "bola-walk", "zap-crawl",
    "katana-crawl", "harvest", "nmap", "dns-brute", "graphql-audit",
}

# The envelope every boxcutter tool returns on stdout - published as each tool's outputSchema so a client gets
# a documented, machine-checkable output contract alongside the human-readable text.
_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "success": {"type": "boolean", "description": "whether the tool run itself succeeded"},
        "data": {"description": "the tool's results (shape depends on the tool: a list of items or findings)"},
        "error": {"type": ["string", "null"], "description": "the failure reason when success is false"},
    },
    "required": ["success"],
}


def _log(msg: str) -> None:
    """Diagnostics ALWAYS go to stderr - on the stdio transport, stdout carries the MCP protocol and a stray
    print there would corrupt the stream."""
    sys.stderr.write(f"[boxcutter mcp] {msg}\n")
    sys.stderr.flush()


def _engine_python() -> str:
    """The interpreter used to RUN each tool (a subprocess of ``boxcutter.py <tool> ...``). Defaults to the
    current interpreter; ``BOXCUTTER_ENGINE_PYTHON`` overrides it (set when the protocol server was re-exec'd
    into a venv that has the ``mcp`` SDK but the tools should still run under the lean engine python)."""
    return os.environ.get("BOXCUTTER_ENGINE_PYTHON") or sys.executable


def _cap(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + f"\n…[truncated {len(s) - n} chars]"


# ---------------------------------------------------------------------------
# raw exec tools (run_shell / run_python) - EXPOSED BY DEFAULT, sandboxed
# ---------------------------------------------------------------------------
# These expose arbitrary command / Python execution in the container - the operator's scripting edge (a raw
# curl, a bespoke fuzz loop, a multi-request chain) that the structured tools don't cover, for an agent such as
# an external "joseph". They are on by DEFAULT (turn them off with BOXCUTTER_MCP_NO_EXEC=1 / --no-exec).
#
# SANDBOX. Each call runs in a dedicated working directory (BOXCUTTER_MCP_SANDBOX, else <DATA_DIR>/mcp-sandbox,
# else a temp dir) as its cwd, HOME and TMPDIR, and - when the server is root - DROPS to a low-privilege user
# (default `nobody`, or BOXCUTTER_MCP_SANDBOX_USER). So a script cannot delete or overwrite files it doesn't own
# (system files, the boxcutter install, the DB / the /data volume) and its writes default to the sandbox dir;
# `rm -rf /` just gets "permission denied". Reads of world-readable files are still allowed (fine for recon; for
# full filesystem isolation put bubblewrap/landlock in front). The scope boundary is still the operator's, on an
# authorised target. State persists in the sandbox dir across calls, so a script can build on an earlier one.
def _exec_enabled() -> bool:
    return str(os.environ.get("BOXCUTTER_MCP_NO_EXEC", "")).strip().lower() not in ("1", "true", "yes", "on")


_EXEC_SPECS = {
    "run_shell": {
        "description": ("Run a shell command (bash) inside the boxcutter container; returns {exit, stdout, "
                        "stderr}. The full toolchain is on PATH (curl, python3, nmap, nuclei, sqlmap, git, ...). "
                        "Runs sandboxed: a dedicated working dir as cwd, dropped to a low-priv user, so it can't "
                        "delete files it doesn't own. For plain HTTP prefer the structured `http-request` tool; "
                        "use this for a raw command or a one-off pipeline. Stay within the authorised scope."),
        "schema": {"type": "object", "additionalProperties": False,
                   "properties": {"command": {"type": "string", "description": "the shell command to run"},
                                  "timeout": {"type": "integer", "description": "max seconds (default 300)"}},
                   "required": ["command"]},
    },
    "run_python": {
        "description": ("Run a Python 3 snippet inside the container (the engine python has `requests`); returns "
                        "{exit, stdout, stderr}. Use for a bespoke fuzz loop, a payload generator, or a "
                        "multi-request chain the built-in tools don't cover. Runs sandboxed (dedicated cwd, "
                        "dropped to a low-priv user). Stay within the authorised target scope."),
        "schema": {"type": "object", "additionalProperties": False,
                   "properties": {"code": {"type": "string", "description": "the Python 3 source to run"},
                                  "timeout": {"type": "integer", "description": "max seconds (default 300)"}},
                   "required": ["code"]},
    },
}


@functools.lru_cache(maxsize=1)
def _sandbox() -> tuple[str, int | None, int | None]:
    """(cwd, uid, gid) for exec. cwd is a dedicated working dir (BOXCUTTER_MCP_SANDBOX, else <DATA_DIR>/
    mcp-sandbox, else a temp dir). uid/gid are a low-priv user to drop to when we are root (default `nobody`),
    so a script can't delete/overwrite files it doesn't own; None when we're already unprivileged (nothing to
    drop) or on a non-POSIX host. Computed once per process."""
    root = os.environ.get("BOXCUTTER_MCP_SANDBOX")
    if not root:
        base = os.environ.get("DATA_DIR")
        root = os.path.join(base, "mcp-sandbox") if base else os.path.join(tempfile.gettempdir(),
                                                                            "boxcutter-mcp-sandbox")
    try:
        os.makedirs(root, exist_ok=True)
    except OSError:
        root = os.path.join(tempfile.gettempdir(), "boxcutter-mcp-sandbox")
        os.makedirs(root, exist_ok=True)
    uid = gid = None
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            import pwd
            pw = pwd.getpwnam(os.environ.get("BOXCUTTER_MCP_SANDBOX_USER", "nobody"))
            uid, gid = pw.pw_uid, pw.pw_gid
        except Exception:  # noqa: BLE001 - no such user -> just don't drop (still cwd-confined)
            uid = gid = None
        if uid is not None:
            with contextlib.suppress(Exception):     # let the dropped user own + write the sandbox dir
                os.chown(root, uid, gid)
                os.chmod(root, 0o770)
    return root, uid, gid


def _exec_env(ok: bool, data=None, error=None) -> tuple[str, dict, bool]:
    env = {"success": ok, "kind": "exec", "data": data or [], "error": error}
    return json.dumps(env), env, (not ok)


def _run_exec_sync(name: str, arguments: dict, timeout: int | None) -> tuple[str, dict | None, bool]:
    """Run a run_shell / run_python call as a bounded, SANDBOXED subprocess and return the boxcutter envelope:
    a dedicated working dir as cwd/HOME/TMPDIR, dropped to a low-priv user when we're root. Isolated per call
    (stdin=DEVNULL so it never touches the protocol pipe), same as _run_tool_sync."""
    import subprocess
    to = int(arguments.get("timeout") or 300)
    if timeout and timeout > 0:
        to = min(to, timeout)
    to = max(1, to)
    if name == "run_shell":
        cmd = (arguments.get("command") or "").strip()
        if not cmd:
            return _exec_env(False, error="empty command")
        argv = ["bash", "-lc", cmd]
    elif name == "run_python":
        code = arguments.get("code") or ""
        if not code.strip():
            return _exec_env(False, error="empty code")
        argv = [_engine_python(), "-c", code]
    else:
        return _exec_env(False, error=f"unknown exec tool: {name}")

    cwd, uid, gid = _sandbox()
    env = dict(os.environ)
    env.update(HOME=cwd, TMPDIR=cwd, PWD=cwd)         # keep writes (configs, temp) inside the sandbox dir
    kw: dict = {"capture_output": True, "text": True, "timeout": to, "stdin": subprocess.DEVNULL,
                "cwd": cwd, "env": env}
    if uid is not None:                               # drop privileges (Python 3.9+ user/group)
        kw["user"], kw["group"] = uid, gid
        kw["extra_groups"] = []                       # drop root's supplementary groups too
    try:
        p = subprocess.run(argv, **kw)  # noqa: S603 - sandboxed exec is this tool's whole purpose
    except subprocess.TimeoutExpired:
        return _exec_env(False, error=f"{name} timed out after {to}s")
    except Exception as exc:  # noqa: BLE001
        return _exec_env(False, error=f"{name} failed to launch: {exc}")
    ok = p.returncode == 0
    data = [{"exit": p.returncode, "stdout": _cap(p.stdout or "", 20000), "stderr": _cap(p.stderr or "", 8000)}]
    return _exec_env(ok, data=data, error=None if ok else f"exit {p.returncode}")


# ---------------------------------------------------------------------------
# skills: boxcutter's vuln-class PLAYBOOKS (ai/skills/*.md) served over MCP
# ---------------------------------------------------------------------------
# Skills are deep methodology (payloads, steps, confirmation markers, gotchas) - boxcutter PACKAGE data, not
# executables. boxcutter's own joseph loads them locally; over MCP we expose them so ANY client gets them too,
# two ways: a read-only `load_skill` TOOL (an autonomous agent calls it) AND MCP PROMPTS (an interactive client
# lists/fetches them). Always on; they carry no target and run nothing.
def _skill_tool_spec() -> dict:
    names = ", ".join(n for n, _ in skills.catalog())
    return {"description": ("Load a boxcutter vuln-class PLAYBOOK by name - deep methodology (exact payloads, "
                            "steps, confirmation markers, gotchas), returned as markdown - the moment you commit "
                            "to hunting a class, so you probe it the way the playbook says, not from memory. "
                            "Available: " + names + "."),
            "schema": {"type": "object", "additionalProperties": False,
                       "properties": {"name": {"type": "string", "description": "skill/class name, e.g. sqli, "
                                               "idor, xss, ssrf, jwt, graphql, swagger, ssti"}},
                       "required": ["name"]}}


def _run_skill(name: str, arguments: dict, timeout: int | None) -> tuple[str, dict | None, bool]:
    """Serve a vuln-class PLAYBOOK (ai/skills/*.md) as the tool result: the markdown body, so any client can pull
    the deep methodology on demand. Read-only reference data - it runs nothing."""
    sk = (arguments.get("name") or "").strip()
    body = skills.load(sk)
    if body:
        return body, {"skill": sk, "chars": len(body)}, False
    avail = ", ".join(n for n, _ in skills.catalog())
    return (f"unknown skill '{sk}'. Available: {avail}", {"skill": sk, "loaded": False}, True)


def _exposed_names(show_all: bool) -> list[str]:
    """Tool names to advertise: those actually installed in this image (like ``boxcutter --list``), or every
    tool with ``--all-tools`` (like ``--list-all`` - useful for docs or a dev box without the binaries)."""
    return [m.NAME for m in TOOLS if show_all or capability.name_available(m.NAME)]


# ---------------------------------------------------------------------------
# tool catalog / documentation (works with no mcp SDK installed)
# ---------------------------------------------------------------------------
def _catalog(names: list[str]) -> list[dict]:
    """The full machine-readable catalog for ``names``: name, description, input JSON-Schema, and whether the
    binary is installed here. Derived entirely from each tool's argparse via toolschema."""
    out = []
    for n in names:
        spec = toolschema.build(n)
        out.append({
            "name": n,
            "description": spec["description"],
            "installed": capability.name_available(n),
            "requirement": None if capability.name_available(n) else capability.requirement_for(n),
            "input_schema": spec["schema"],
        })
    return out


def _markdown_docs(names: list[str]) -> str:
    """Human-readable reference for every exposed tool: description + a parameter table, generated from the
    same schemas the server advertises (so the docs can't drift from the contract)."""
    lines = [
        "# boxcutter MCP tools",
        "",
        "Every tool below is exposed by `boxcutter mcp` over the Model Context Protocol. Names, descriptions "
        "and parameters are generated directly from each tool's own argparse definition, so this document "
        "always matches what the server actually accepts.",
        "",
        "Each tool returns the boxcutter JSON envelope `{success, data, error}` as both text content and "
        "structured content.",
        "",
        f"**Exposed tools:** {len(names)}",
        "",
    ]
    for n in names:
        spec = toolschema.build(n)
        schema = spec["schema"]
        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        flags = "read-only" if (n not in _MUTATING and n not in _ACTIVE_READ) else \
                ("mutating / active-attack" if n in _MUTATING else "active (read-only)")
        lines += [f"## `{n}`", "", f"_{flags}_", "", spec["description"], ""]
        if props:
            lines += ["| parameter | type | required | description |", "|---|---|---|---|"]
            for dest, p in props.items():
                typ = p.get("type", "string")
                if "enum" in p:
                    typ += " (" + " \\| ".join(str(e) for e in p["enum"]) + ")"
                req = "yes" if dest in required else ""
                desc = (p.get("description") or "").replace("|", "\\|").replace("\n", " ")
                lines.append(f"| `{dest}` | {typ} | {req} | {desc} |")
            lines.append("")
        else:
            lines += ["_(no parameters)_", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# tool execution (subprocess dispatch to boxcutter's own CLI)
# ---------------------------------------------------------------------------
def _run_tool_sync(name: str, arguments: dict, timeout: int | None) -> tuple[str, dict | None, bool]:
    """Run one tool as an isolated subprocess (``<engine-python> boxcutter.py <tool> ...``) and return
    (text, structured, is_error). Isolation - one process per call - keeps concurrent MCP calls from sharing
    any global state, and reuses the exact CLI behaviour (capability checks, the JSON envelope) verbatim."""
    try:
        argv = toolschema.to_argv(name, arguments or {})
    except Exception as exc:  # noqa: BLE001
        return (json.dumps({"success": False, "error": f"bad arguments for {name}: {exc}"}), None, True)

    cmd = [_engine_python(), _BOXCUTTER, *argv]
    try:
        # stdin=DEVNULL: a spawned tool must NOT inherit the server's stdin - on the stdio transport that is
        # the live MCP protocol pipe, and letting a child hold it open (or read it) hangs the call.
        proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                              timeout=timeout if timeout and timeout > 0 else None)
    except subprocess.TimeoutExpired:
        return (json.dumps({"success": False, "error": f"{name} timed out after {timeout}s"}), None, True)
    except Exception as exc:  # noqa: BLE001
        return (json.dumps({"success": False, "error": f"{name} failed to launch: {exc}"}), None, True)

    out = (proc.stdout or "").strip()
    parsed: dict | None = None
    try:
        obj = json.loads(out)
        if isinstance(obj, dict):
            parsed = obj
    except Exception:  # noqa: BLE001 - not JSON (e.g. a crash before the envelope): surface stdout+stderr
        pass

    if parsed is None:
        detail = out or (proc.stderr or "").strip() or f"exit {proc.returncode}, no output"
        return (json.dumps({"success": False, "error": f"{name} produced no JSON envelope", "detail": detail[:4000]}),
                None, True)

    # A well-formed envelope with success:false is a tool that RAN and reported failure (unreachable target,
    # binary missing, ...) - surface the whole envelope but flag it so the agent notices.
    is_error = parsed.get("success") is False or proc.returncode != 0
    return (out, parsed, is_error)


# ---------------------------------------------------------------------------
# MCP server (needs the optional `mcp` SDK)
# ---------------------------------------------------------------------------
def _import_mcp():
    """Import the MCP SDK, or return None. Kept lazy so the lean engine never imports it and ``--print-docs`` /
    ``--print-catalog`` work with the SDK absent."""
    try:
        import mcp  # noqa: F401
        return mcp
    except Exception:  # noqa: BLE001
        return None


def _reexec_into_sdk_python(argv: list[str]) -> int | None:
    """If the current interpreter lacks the ``mcp`` SDK, re-exec ``boxcutter mcp`` under one that has it - the
    bundled server venv (/opt/srv) in the published image, where the SDK is installed alongside its transport
    stack. Tools still run under the LEAN engine python (BOXCUTTER_ENGINE_PYTHON), so this only moves the
    PROTOCOL server, not tool execution. Returns None if no re-exec was needed/possible (caller then prints the
    install hint). Mirrors how ``boxcutter serve`` execs the venv for uvicorn."""
    if _import_mcp() is not None:
        return None                                   # current interpreter already has the SDK
    for cand in (os.environ.get("BOXCUTTER_MCP_PYTHON"), "/opt/srv/bin/python", "/opt/srv/bin/python3"):
        if cand and os.path.exists(cand) and os.path.abspath(cand) != os.path.abspath(sys.executable):
            env = dict(os.environ)
            env.setdefault("BOXCUTTER_ENGINE_PYTHON", sys.executable)   # keep tools on the lean engine
            _log(f"re-exec into {cand} for the MCP SDK (tools stay on {sys.executable})")
            os.execve(cand, [cand, _BOXCUTTER, "mcp", *argv], env)      # replaces this process
    return None


def build_server(names: list[str], timeout: int | None):
    """A low-level MCP ``Server`` advertising ``names`` and dispatching each call to the boxcutter CLI. The
    low-level API (explicit Tool objects) is the right fit here because our schemas are generated at runtime
    from argparse, not from Python function signatures."""
    import contextlib

    import anyio
    from mcp.server.lowlevel import Server
    from mcp import types

    server = Server(SERVER_NAME)
    specs = {n: toolschema.build(n) for n in names}

    # raw exec tools (run_shell / run_python): exposed by default, sandboxed. Off with BOXCUTTER_MCP_NO_EXEC.
    exec_names: set[str] = set()
    if _exec_enabled():
        for en, e in _EXEC_SPECS.items():
            specs[en] = {"description": e["description"], "schema": e["schema"]}
            exec_names.add(en)
        cwd, uid, _gid = _sandbox()
        drop = f"drops to uid {uid}" if uid is not None else "runs as the current (non-root) user"
        _log(f"exec tools run_shell / run_python exposed (sandbox: cwd {cwd}, {drop}). This is code execution "
             "inside the container - keep the API key secret and the endpoint restricted to an authorised scope.")

    # skills: a read-only load_skill tool (autonomous agents) + MCP prompts (interactive clients), always on.
    specs["load_skill"] = _skill_tool_spec()

    async def _keepalive(ctx, token, rid, name: str) -> None:
        """Emit a heartbeat every KEEPALIVE_SECS while a tool runs, on THIS request's stream, so a proxy's read
        timeout (Cloudflare ~100s / nginx 60s) never cuts a long call. A progress notification needs the client's
        progressToken; a log message does not - we send both, so bytes flow regardless of client. Best-effort:
        a client that ignores notifications still keeps the connection alive by receiving the bytes."""
        if not KEEPALIVE_SECS:
            return
        elapsed = 0.0
        while True:
            await anyio.sleep(KEEPALIVE_SECS)
            elapsed += KEEPALIVE_SECS
            note = f"{name} still running ({int(elapsed)}s)…"
            if token is not None:
                with contextlib.suppress(Exception):
                    await ctx.session.send_progress_notification(
                        progress_token=token, progress=elapsed, total=None,
                        message=note, related_request_id=rid)
            with contextlib.suppress(Exception):
                await ctx.session.send_log_message(
                    level="info", data=note, logger="boxcutter", related_request_id=rid)

    def _annotations(n: str):
        if n == "load_skill":            # read-only reference data; no target, runs nothing
            return types.ToolAnnotations(title=n, readOnlyHint=True, destructiveHint=False,
                                         idempotentHint=True, openWorldHint=False)
        if n in exec_names:              # raw exec: never read-only, always potentially destructive
            return types.ToolAnnotations(title=n, readOnlyHint=False, destructiveHint=True,
                                         idempotentHint=False, openWorldHint=True)
        read_only = n not in _MUTATING and n not in _ACTIVE_READ
        return types.ToolAnnotations(
            title=n,
            readOnlyHint=read_only,
            destructiveHint=n in _MUTATING,
            idempotentHint=False,
            openWorldHint=True,          # every tool reaches out to an external target
        )

    @server.list_tools()
    async def list_tools() -> list["types.Tool"]:
        return [
            types.Tool(
                name=n,
                title=n,
                description=specs[n]["description"],
                inputSchema=specs[n]["schema"],
                outputSchema=_OUTPUT_SCHEMA,
                annotations=_annotations(n),
            )
            for n in specs                # registry tools + any opt-in exec tools
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> "types.CallToolResult":
        if name not in specs:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(
                    {"success": False, "error": f"'{name}' is not an exposed boxcutter tool"}))],
                isError=True)

        # Run the tool in a worker thread while a heartbeat keeps the request's stream alive (long scans
        # otherwise 524 behind a proxy). request_context is available inside the handler; guard it so the
        # keepalive degrades to a no-op if a transport doesn't expose it.
        ctx = token = rid = None
        with contextlib.suppress(Exception):
            ctx = server.request_context
            rid = getattr(ctx, "request_id", None)
            token = getattr(getattr(ctx, "meta", None), "progressToken", None)

        box: dict = {}
        runner = _run_skill if name == "load_skill" else (
            _run_exec_sync if name in exec_names else _run_tool_sync)

        async def _run() -> None:
            box["res"] = await anyio.to_thread.run_sync(runner, name, arguments, timeout)

        if ctx is not None and KEEPALIVE_SECS:
            async with anyio.create_task_group() as tg:
                tg.start_soon(_keepalive, ctx, token, rid, name)
                await _run()
                tg.cancel_scope.cancel()          # tool done -> stop the heartbeat
        else:
            await _run()

        text, structured, is_error = box["res"]
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)],
            structuredContent=structured,
            isError=is_error,
        )

    # PROMPTS: the same vuln-class playbooks as MCP prompts, so a prompt-aware client (not just an autonomous
    # agent using the load_skill tool) can list them and inject one. Registering these advertises the capability.
    @server.list_prompts()
    async def list_prompts() -> list["types.Prompt"]:
        return [types.Prompt(name=n, description=d) for n, d in skills.catalog()]

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict | None = None) -> "types.GetPromptResult":
        body = skills.load(name) or (
            "unknown skill '%s'. Available: %s" % (name, ", ".join(n for n, _ in skills.catalog())))
        return types.GetPromptResult(
            description=f"boxcutter vuln-class playbook: {name}",
            messages=[types.PromptMessage(role="user",
                                          content=types.TextContent(type="text", text=body))])

    return server


def _serve_stdio(server) -> int:
    import anyio
    from mcp.server.stdio import stdio_server

    async def _run():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    _log("serving on stdio (spawn-as-subprocess transport); Ctrl-C to stop")
    anyio.run(_run)
    return 0


class _ApiKeyMiddleware:
    """A minimal shared-secret gate for the HTTP transport: require the key as ``Authorization: Bearer <key>``
    or ``X-API-Key: <key>`` on the MCP path. This is a pragmatic deployment key (put the endpoint behind TLS /
    a reverse proxy for real exposure), not full MCP OAuth. ``/health`` stays open for liveness probes."""

    def __init__(self, app, api_key: str, protected_prefix: str):
        self.app = app
        self.api_key = api_key
        self.prefix = protected_prefix

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and self.api_key and scope.get("path", "").startswith(self.prefix):
            headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
            auth = headers.get("authorization", "")
            provided = auth[7:].strip() if auth[:7].lower() == "bearer " else headers.get("x-api-key", "")
            if not (provided and hmac.compare_digest(provided, self.api_key)):
                body = json.dumps({"error": "unauthorized: missing or invalid API key"}).encode()
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"www-authenticate", b'Bearer realm="boxcutter-mcp"')]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


def _serve_http(server, host: str, port: int, api_key: str | None, path: str,
                json_response: bool, stateless: bool, tool_count: int) -> int:
    import contextlib

    import uvicorn
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    manager = StreamableHTTPSessionManager(
        app=server, event_store=None, json_response=json_response, stateless=stateless)

    async def handle_mcp(scope, receive, send):
        await manager.handle_request(scope, receive, send)

    async def health(_req: Request):
        return JSONResponse({"status": "ok", "server": SERVER_NAME, "tools": tool_count})

    async def info(_req: Request):
        return JSONResponse({
            "server": SERVER_NAME, "transport": "streamable-http", "mcp_endpoint": path,
            "auth": "api-key" if api_key else "none",
        })

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            mode = "stateless" if stateless else "stateful"
            _log(f"MCP endpoint ready at http://{host}:{port}{path}  ({mode}, "
                 f"{'API key required' if api_key else 'no auth'})")
            yield

    app = Starlette(
        debug=False,
        routes=[Route("/", info), Route("/health", health), Mount(path, app=handle_mcp)],
        lifespan=lifespan,
    )
    if api_key:
        app.add_middleware(_ApiKeyMiddleware, api_key=api_key, protected_prefix=path)

    uvicorn.run(app, host=host, port=port, log_level="info",
                proxy_headers=True, forwarded_allow_ips="*")
    return 0


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="boxcutter mcp",
        description="Serve boxcutter's deterministic tools over the Model Context Protocol (stdio or HTTP).")
    ap.add_argument("--http", action="store_true",
                    help="Serve over Streamable HTTP (networked) instead of stdio (default).")
    ap.add_argument("--host", default=os.environ.get("BOXCUTTER_MCP_HOST", "127.0.0.1"),
                    help="HTTP bind host (default: 127.0.0.1; use 0.0.0.0 to expose).")
    ap.add_argument("--port", type=int, default=int(os.environ.get("BOXCUTTER_MCP_PORT", "9000")),
                    help="HTTP bind port (default: 9000).")
    ap.add_argument("--path", default=os.environ.get("BOXCUTTER_MCP_PATH", "/mcp"),
                    help="HTTP path the MCP endpoint is mounted at (default: /mcp).")
    ap.add_argument("--api-key", default=os.environ.get("BOXCUTTER_MCP_API_KEY"),
                    help="Shared secret required on the HTTP transport (Authorization: Bearer / X-API-Key). "
                         "Also read from BOXCUTTER_MCP_API_KEY. Omit for an open endpoint.")
    ap.add_argument("--no-exec", action="store_true",
                    help="Do NOT expose the raw exec tools run_shell / run_python. They are exposed by default "
                         "(sandboxed: a dedicated working dir, dropped to a low-priv user), which is code "
                         "execution in the container - keep the endpoint API-key-gated and scope-restricted. "
                         "Also settable with BOXCUTTER_MCP_NO_EXEC=1.")
    ap.add_argument("--json-response", action="store_true",
                    help="HTTP: reply with plain JSON instead of an SSE stream (simpler clients).")
    ap.add_argument("--stateful", action="store_true",
                    help="HTTP: keep per-session state (default is stateless - each request is independent, "
                         "which is best behind a load balancer).")
    ap.add_argument("--all-tools", action="store_true",
                    help="Expose EVERY tool, including ones whose binary isn't installed in this image "
                         "(default: only installed tools, like `boxcutter --list`).")
    ap.add_argument("--tool-timeout", type=int, default=int(os.environ.get("BOXCUTTER_MCP_TOOL_TIMEOUT", "1800")),
                    help="Per-tool-call timeout in seconds (default: 1800; 0 = no limit).")
    ap.add_argument("--print-catalog", action="store_true",
                    help="Print the exposed tools as JSON (name/description/schema) and exit. No SDK needed.")
    ap.add_argument("--print-docs", action="store_true",
                    help="Print Markdown documentation of the exposed tools and exit. No SDK needed.")
    ap.add_argument("--write-docs", metavar="PATH",
                    help="Write the Markdown tool documentation to PATH and exit. No SDK needed.")
    ap.add_argument("--list-tools", action="store_true",
                    help="Print the names of the exposed tools and exit. No SDK needed.")
    a = ap.parse_args([] if argv is None else list(argv))
    if a.no_exec:
        os.environ["BOXCUTTER_MCP_NO_EXEC"] = "1"        # so build_server's _exec_enabled() turns them off

    # For docs/catalog, document the WHOLE registry by default (that's the reference); the running server
    # advertises only what's installed unless --all-tools is given.
    doc_all = a.all_tools or a.print_docs or a.print_catalog or a.write_docs
    names = _exposed_names(show_all=doc_all)

    if a.list_tools:
        print("\n".join(names))
        return 0
    if a.print_catalog:
        print(json.dumps({"server": SERVER_NAME, "tools": _catalog(names)}, indent=2))
        return 0
    if a.print_docs:
        print(_markdown_docs(names))
        return 0
    if a.write_docs:
        with open(a.write_docs, "w", encoding="utf-8") as fh:
            fh.write(_markdown_docs(names))
        _log(f"wrote {len(names)}-tool documentation to {a.write_docs}")
        return 0

    # From here we actually serve, which needs the optional SDK. If this interpreter doesn't have it, re-exec
    # into one that does (the server venv in the image); if none exists, print the install hint.
    _reexec_into_sdk_python([] if argv is None else list(argv))
    if _import_mcp() is None:
        _log("the MCP SDK is not installed. Install it with:\n"
             "    pip install -r requirements.txt\n"
             "(kept out of the lean engine on purpose, like the web server's deps).")
        return 1

    names = _exposed_names(show_all=a.all_tools)
    if not names:
        _log("no tools are installed in this image, so nothing would be exposed. Use --all-tools to advertise "
             "the full registry anyway (calls to uninstalled tools return a clear 'not installed' error).")
        return 1

    timeout = a.tool_timeout if a.tool_timeout and a.tool_timeout > 0 else None
    server = build_server(names, timeout)
    _log(f"boxcutter MCP server - {len(names)} tool(s) exposed"
         + (f", tool timeout {timeout}s" if timeout else ", no tool timeout"))

    try:
        if a.http:
            return _serve_http(server, a.host, a.port, a.api_key, a.path,
                               json_response=a.json_response, stateless=not a.stateful,
                               tool_count=len(names))
        return _serve_stdio(server)
    except KeyboardInterrupt:
        _log("shutting down")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

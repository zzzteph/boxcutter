"""``boxcutter mcp`` - expose boxcutter's deterministic tool registry as a fully MCP-compliant server, so any
agentic client (Claude Desktop, an IDE agent, a custom LLM app, another orchestrator) can drive the toolkit
over the Model Context Protocol.

Two transports, one server:

    boxcutter mcp                              # stdio (default) - for clients that SPAWN boxcutter as a subprocess
    boxcutter mcp --http --port 9000           # Streamable HTTP - a NETWORKED endpoint agents connect to
    boxcutter mcp --http --api-key $SECRET     # ...with an optional shared-secret gate

On the HTTP transport an optional API key (``--api-key`` or ``BOXCUTTER_MCP_API_KEY``) is required as either
``Authorization: Bearer <key>`` or ``X-API-Key: <key>``; without one the endpoint is open (localhost-friendly).

WHAT IS EXPOSED: only the deterministic tools (recon, crawl, scanners, fuzzers, http-request, ...). The
LLM-driven ``ai`` agents are deliberately NOT deployable here - they need a provider/API key and per-run
preconfiguration, which a stateless MCP endpoint can't carry. Each tool's name, description and JSON-Schema
are derived straight from the tool's own argparse via ``tools.toolschema``, so the advertised contract can
never drift from what the CLI actually accepts.

The ``mcp`` SDK is an OPTIONAL dependency, kept out of the lean engine exactly like the web server's deps.
Install it with::

    pip install -r requirements.txt      # then: boxcutter mcp

Full generated documentation of every exposed tool: ``boxcutter mcp --print-docs`` (or see docs/MCP_TOOLS.md).
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import subprocess
import sys

from .core import capability
from .tools import toolschema
from .tools.registry import TOOLS

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # repo root: has boxcutter.py, server/
_BOXCUTTER = os.path.join(_ROOT, "boxcutter.py")

SERVER_NAME = "boxcutter"

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
    import anyio
    from mcp.server.lowlevel import Server
    from mcp import types

    server = Server(SERVER_NAME)
    specs = {n: toolschema.build(n) for n in names}

    def _annotations(n: str):
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
            for n in names
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> "types.CallToolResult":
        if name not in specs:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(
                    {"success": False, "error": f"'{name}' is not an exposed boxcutter tool"}))],
                isError=True)
        text, structured, is_error = await anyio.to_thread.run_sync(
            _run_tool_sync, name, arguments, timeout)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)],
            structuredContent=structured,
            isError=is_error,
        )

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

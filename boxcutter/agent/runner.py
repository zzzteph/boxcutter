"""The boxcutter bridge - runs ONE sub-command and returns its stdout (the JSON envelope).

Safety is enforced here, not in the prompt: a global allowlist of boxcutter sub-commands, an optional
per-agent subset, and (unless aggressive mode is enabled) a block on state-mutating HTTP methods.
boxcutter-only by construction.

When bob runs as the `boxcutter bob` subcommand it dispatches IN-PROCESS (no docker-in-docker): it calls
the boxcutter CLI in the same interpreter and captures the JSON envelope it prints.
"""

from __future__ import annotations

import contextlib
import io
import json

OUT_CAP = 12000          # chars of a tool's output fed back to the model
MUTATING = {"put", "patch", "delete"}

ALLOWED = {
    "httpx", "subfinder", "dnsx", "wayback", "wayback-domains", "katana-crawl", "js-endpoints",
    "dirsearch", "dirb", "path-fuzz", "nuclei", "git-extract", "scan-secrets", "screenshot",
    "fuzz", "sqlmap", "zap-scan-url", "zap-scan-full", "zap-scan-openapi", "swagger-parser",
    "swagger-endpoints", "swagger-specs", "graphql-detect", "graphql-audit", "http-request",
    "workflow", "--list", "--help",
}
_ALWAYS = {"--list", "--help", "workflow"}


def _truncate(out):
    """Cap a tool result without feeding the model invalid JSON.

    A naive out[:CAP] slices a big nuclei/katana envelope mid-object. Prefer trimming the `data`
    list and re-serialising so the model still gets parseable JSON plus a truncation marker.
    """
    if len(out) <= OUT_CAP:
        return out
    try:
        obj = json.loads(out)
    except Exception:  # noqa: BLE001 - not JSON, fall back to a flagged head slice
        return out[:OUT_CAP] + f"\n...[truncated {len(out) - OUT_CAP} chars]"
    data = obj.get("data")
    if isinstance(data, list) and len(data) > 1:
        for keep in (50, 20, 10, 5):
            obj["data"] = data[:keep]
            obj["_truncated"] = f"showing {min(keep, len(data))} of {len(data)} items"
            s = json.dumps(obj)
            if len(s) <= OUT_CAP:
                return s
        return json.dumps(obj)[:OUT_CAP]
    return out[:OUT_CAP] + f"\n...[truncated {len(out) - OUT_CAP} chars]"


def _check(argv, allowed, aggressive):
    """Return an error-envelope string if argv is not permitted, else None."""
    tool = argv[0] if argv else ""
    if tool not in ALLOWED:
        return json.dumps({"success": False, "error": f"'{tool or '(empty)'}' is not a boxcutter sub-command"})
    if allowed is not None and tool not in allowed and tool not in _ALWAYS:
        return json.dumps({"success": False, "error": f"'{tool}' is not permitted for this agent"})
    if not aggressive:
        for i, t in enumerate(argv):
            if t in ("--method", "-X") and i + 1 < len(argv) and argv[i + 1].lower() in MUTATING:
                return json.dumps({"success": False,
                                   "error": "mutating method blocked (run bob with --aggressive to allow PUT/PATCH/DELETE)"})
    return None


class InProcessRunner:
    """`runner(argv, allowed=agent.tools)` -> JSON envelope text, dispatched in-process."""

    def __init__(self, tool_timeout=600, aggressive=False):
        self.tool_timeout = tool_timeout
        self.aggressive = aggressive

    def __call__(self, argv, allowed=None):
        err = _check(argv, allowed, self.aggressive)
        if err:
            return err
        from ..cli import main as cli_main  # deferred: avoids a circular import at module load
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                cli_main(list(argv))
        except SystemExit:
            pass
        except Exception as exc:  # noqa: BLE001 - a tool blowing up must not kill the pipeline
            return json.dumps({"success": False, "error": f"{argv[0]} failed: {exc}"})
        out = buf.getvalue().strip()
        return out[:OUT_CAP] if out else json.dumps({"success": True, "data": [], "error": None})

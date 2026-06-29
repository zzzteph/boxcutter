"""orca's boxcutter bridge - runs ONE sub-command in-process and returns its JSON envelope.

Standalone (no bob imports). Enforces the same safety as bob's runner does at the choke point - an
allowlist of boxcutter sub-commands, a block on state-mutating methods unless aggressive, a same-host
scope guard, response caching, and the friendly guards (no `http-request -X`, no bare `--data {FUZZ}`) -
plus the same-functionality URL dedupe. Executors call `runner(argv)`; the planner never touches tools.
"""

from __future__ import annotations

import contextlib
import io
import json
from urllib.parse import urlparse, parse_qsl

OUT_CAP = 12000
MUTATING = {"put", "patch", "delete"}

ALLOWED = {
    "httpx", "dnsx", "wayback", "wayback-domains", "katana-crawl", "js-endpoints",
    "dirsearch", "dirb", "path-fuzz", "nuclei", "git-extract", "scan-secrets", "screenshot",
    "fuzz", "sqlmap", "swagger-parser", "swagger-endpoints", "swagger-specs",
    "graphql-detect", "graphql-audit", "http-request",
    "--list", "--help",
}
_ALWAYS = {"--list", "--help"}


def _url_of(argv):
    return next((a for a in argv[1:] if isinstance(a, str) and a.startswith(("http://", "https://"))), "")


def _struct_sig(argv):
    """Same path basename + same query-param names = same functionality (skip the redundant test)."""
    url = _url_of(argv)
    if not url:
        return None
    u = urlparse(url)
    params = frozenset(k.lower() for k, _ in parse_qsl(u.query))
    if not params:
        return None
    basename = (u.path.rstrip("/").rsplit("/", 1)[-1] or "/").lower()
    return (argv[0], (u.hostname or "").lower(), basename, params)


def _truncate(out):
    if len(out) <= OUT_CAP:
        return out
    try:
        obj = json.loads(out)
    except Exception:  # noqa: BLE001
        return out[:OUT_CAP] + f"\n...[truncated {len(out) - OUT_CAP} chars]"
    data = obj.get("data")
    if isinstance(data, list) and len(data) > 1:
        for keep in (50, 20, 10, 5):
            obj["data"] = data[:keep]
            obj["_truncated"] = f"showing {min(keep, len(data))} of {len(data)} items"
            s = json.dumps(obj)
            if len(s) <= OUT_CAP:
                return s
    return out[:OUT_CAP] + f"\n...[truncated {len(out) - OUT_CAP} chars]"


def _err(msg):
    return json.dumps({"success": False, "error": msg})


class Runner:
    """`runner(argv, ctx=state)` -> JSON envelope text, dispatched in-process to the boxcutter CLI."""

    def __init__(self, aggressive=True, max_calls=600, base_host=""):
        self.aggressive = aggressive
        self.max_calls = max_calls
        self.base_host = base_host
        self._calls = 0
        self._cache = {}
        self._sigs = {}

    def __call__(self, argv, ctx=None, allowed=None):
        argv = [str(a) for a in argv]
        tool = argv[0] if argv else ""
        if tool not in ALLOWED:
            return _err(f"'{tool or '(empty)'}' is not a boxcutter sub-command")
        if allowed is not None and tool not in allowed and tool not in _ALWAYS:
            return _err(f"'{tool}' is not one of this executor's tools ({', '.join(sorted(allowed))})")
        if tool == "http-request" and any(t in ("-X", "--method") for t in argv):
            return _err("http-request does GET or POST (-D/--data) only - no -X/--method override; drop it.")
        if tool == "fuzz":
            for i, t in enumerate(argv):
                if t == "--data" and i + 1 < len(argv) and argv[i + 1].strip() in ("{FUZZ}", "{NUMBERS}"):
                    return _err("bare '--data {FUZZ}' sends one payload as the whole body; put {FUZZ} in ONE field "
                                "of a real body, e.g. --data '{\"q\":\"{FUZZ}\"}'.")
        if not self.aggressive:
            for i, t in enumerate(argv):
                if t in ("--method", "-X") and i + 1 < len(argv) and argv[i + 1].lower() in MUTATING:
                    return _err("mutating method blocked (orca not in aggressive mode)")
        # scope: keep active calls on the target host
        thost = (urlparse(_url_of(argv)).hostname or "").lower()
        if self.base_host and thost and thost != self.base_host and not thost.endswith("." + self.base_host):
            return _err(f"'{thost}' is out of scope (target {self.base_host})")
        # same-functionality dedupe for active tests
        if tool in ("fuzz", "sqlmap"):
            sig = _struct_sig(argv)
            if sig is not None:
                first, cur = self._sigs.get(sig), _url_of(argv)
                if first and first != cur:
                    return _err(f"skipped: '{cur}' is structurally identical to already-tested '{first}'.")
                self._sigs.setdefault(sig, cur)

        key = tuple(argv)
        if key in self._cache:
            if ctx is not None:
                ctx.record(argv, self._cache[key])
            return self._cache[key]
        self._calls += 1
        if self._calls > self.max_calls:
            return _err(f"run budget reached ({self.max_calls} tool calls)")
        out = self._dispatch(argv)
        self._cache[key] = out
        if ctx is not None:
            ctx.record(argv, out)
        return out

    def _dispatch(self, argv):
        from ..cli import main as cli_main          # boxcutter toolkit (shared by both tools), not bob code
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                cli_main(list(argv))
        except SystemExit:
            pass
        except Exception as exc:  # noqa: BLE001 - a tool blowing up must not kill the run
            return _err(f"{argv[0]} failed: {exc}")
        raw = buf.getvalue().strip()
        return _truncate(raw) if raw else json.dumps({"success": True, "data": [], "error": None})

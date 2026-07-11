"""irvin's boxcutter bridge - runs ONE sub-command in-process and returns its JSON envelope.

The deterministic choke point every executor's tool call passes through: an allowlist of boxcutter
sub-commands, a block on state-mutating methods unless aggressive, a same-host scope guard, response
caching, and the friendly guards (no `http-request -X`, no bare `--data {FUZZ}`) - plus the
same-functionality URL dedupe. Executors call `runner(argv)`; the planner never touches tools.
"""

from __future__ import annotations

import contextlib
import fnmatch
import io
import json
import time
from urllib.parse import urlparse, parse_qsl

OUT_CAP = 12000
MUTATING = {"put", "patch", "delete"}

_HEADER_FLAG: dict = {}


def _header_flag(tool: str):
    """The header flag a tool accepts ('--header'/'-H'), or None - derived once from its real argparse so the
    runner can attach global headers only to tools that actually take them (http-request, fuzz, browser-*)."""
    if tool not in _HEADER_FLAG:
        try:
            from ..tools import toolschema
            _HEADER_FLAG[tool] = toolschema.build(tool)["flag_of"].get("header")
        except Exception:  # noqa: BLE001
            _HEADER_FLAG[tool] = None
    return _HEADER_FLAG[tool]

ALLOWED = {
    "subfinder", "httpx", "dnsx", "wayback", "wayback-domains", "katana-crawl", "js-endpoints",
    "dirsearch", "dirb", "path-fuzz", "nuclei", "git-extract", "scan-secrets", "screenshot",
    "fuzz", "sqlmap", "swagger-parser", "swagger-endpoints", "swagger-specs",
    "graphql-detect", "graphql-audit", "http-request",
    "browser-crawl", "browser-login", "browser-actions", "visual-driver",
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

    def __init__(self, aggressive=True, max_calls=600, base_host="", extra_hosts=None, global_headers=None):
        self.aggressive = aggressive
        self.max_calls = max_calls
        self.base_host = base_host
        # additional in-scope hosts the operator opted into (e.g. a SPA's cross-origin API backend via --scope).
        # An entry may be an EXACT host or a wildcard/glob (e.g. *.example.com) - see _in_scope.
        self.extra_hosts = {h.strip().lower() for h in (extra_hosts or []) if h and h.strip()}
        # headers attached to EVERY header-capable tool call (e.g. a Tester-Token that disables recaptcha on
        # staging, or an org auth header) - a global credential the model never has to know or repeat.
        self.global_headers = [h.strip() for h in (global_headers or []) if h and h.strip()]
        self._calls = 0
        self._cache = {}
        self._sigs = {}

    def _in_scope(self, host: str) -> bool:
        """In scope if the host is the target, or matches a --scope entry - which may be an EXACT host OR a
        wildcard/glob. `*.example.com` covers every subdomain AND the apex example.com, so 'add all of a
        domain' is one entry. The default is still the smallest sensible scope (just the target host); nothing
        is widened implicitly - a wildcard is only ever in scope because the operator explicitly asked for it."""
        if not host:
            return True
        host = host.lower()
        if host == self.base_host:
            return True
        for entry in self.extra_hosts:
            if host == entry:
                return True
            if entry.startswith("*.") and host == entry[2:]:      # *.d.com also covers the bare apex d.com
                return True
            if any(c in entry for c in "*?[") and fnmatch.fnmatch(host, entry):
                return True
        return False

    def _with_headers(self, argv):
        """Append the global headers to a call, but only for tools that accept a header flag and only for a
        header the call doesn't already carry - so a Tester-Token/org header (or identity A's session) rides
        on every request without the model having to set it, and without duplicating one it did set.

        The 'already carries' check is by header NAME, not exact string: when an executor deliberately attaches
        a DIFFERENT value for the same header (e.g. access-control putting identity B's own Cookie on a call to
        diff against A), the call's explicit value must win - injecting the global A Cookie alongside it would
        send two Cookie headers and corrupt the cross-actor comparison."""
        if not self.global_headers:
            return argv
        flag = _header_flag(argv[0])
        if not flag:
            return argv
        present = set()
        for i, a in enumerate(argv[:-1]):
            if a == flag and isinstance(argv[i + 1], str) and ":" in argv[i + 1]:
                present.add(argv[i + 1].split(":", 1)[0].strip().lower())
        extra = []
        for h in self.global_headers:
            if h in argv or h.split(":", 1)[0].strip().lower() in present:
                continue
            extra += [flag, h]
        return argv + extra if extra else argv

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
                    return _err("mutating method blocked (irvin not in aggressive mode)")
        # scope: keep active calls on the target host (or a host the operator added with --scope)
        thost = (urlparse(_url_of(argv)).hostname or "").lower()
        if self.base_host and thost and not self._in_scope(thost):
            return _err(f"'{thost}' is out of scope (target {self.base_host}; add --scope {thost} to include it)")
        # same-functionality dedupe for active tests
        if tool in ("fuzz", "sqlmap"):
            sig = _struct_sig(argv)
            if sig is not None:
                first, cur = self._sigs.get(sig), _url_of(argv)
                if first and first != cur:
                    return _err(f"skipped: '{cur}' is structurally identical to already-tested '{first}'.")
                self._sigs.setdefault(sig, cur)

        # A persistent-session browser call is STATEFUL: the same argv at two different times drives a browser
        # that has moved on (logged in, navigated, mutated the page), so identical calls must NOT be de-duped
        # to a cached result the way a pure read (an http GET, a recon scan) can be. Any tool carrying
        # --session (browser-actions, visual-driver) is stateful.
        stateful = "--session" in argv
        key = tuple(argv)
        if not stateful and key in self._cache:
            if ctx is not None:
                ctx.record(argv, self._cache[key], cached=True)   # cache hit: instant, NOT a real run time
            return self._cache[key]
        self._calls += 1
        if self._calls > self.max_calls:
            return _err(f"run budget reached ({self.max_calls} tool calls)")
        # dispatch WITH the global headers attached, but key the cache / record the trail on the clean argv so
        # a secret global header (a Tester-Token) never lands in the cache key or the decision trail. Time the
        # real dispatch so a heavy tool that returns suspiciously fast (a no-op / bad-arg failure) is visible.
        t0 = time.monotonic()
        out = self._dispatch(self._with_headers(argv))
        ms = int((time.monotonic() - t0) * 1000)
        if not stateful:
            self._cache[key] = out
        if ctx is not None:
            ctx.record(argv, out, ms=ms)
        return out

    def _dispatch(self, argv):
        from ..cli import main as cli_main          # boxcutter's own CLI dispatcher
        out_buf, err_buf = io.StringIO(), io.StringIO()
        code = 0
        try:
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                code = cli_main(list(argv))
        except SystemExit as exc:
            # argparse (e.g. "unrecognized arguments") reports errors by printing to stderr and exiting - a
            # blanket `except SystemExit: pass` here used to swallow that into a clean-empty success, so the
            # model never learned its call was malformed. Keep the real exit code so a non-zero one below can
            # surface the actual argparse message instead.
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        except Exception as exc:  # noqa: BLE001 - a tool blowing up must not kill the run
            return _err(f"{argv[0]} failed: {exc}")
        raw = out_buf.getvalue().strip()
        if raw:
            return _truncate(raw)
        if code:
            err = err_buf.getvalue().strip()
            tail = "\n".join(err.splitlines()[-3:]) if err else "no output"
            return _err(f"{argv[0]} rejected the call (exit {code}): {tail}")
        return json.dumps({"success": True, "data": [], "error": None})

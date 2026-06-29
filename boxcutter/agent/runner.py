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
import os
from urllib.parse import urlparse, parse_qsl

OUT_CAP = 12000          # chars of a tool's output fed back to the model
MUTATING = {"put", "patch", "delete"}

# tools that accept --header, so the managed session token can be auto-injected
_HEADER_TOOLS = {
    "http-request", "fuzz", "nuclei", "katana-crawl", "dirsearch", "screenshot",
    "browser-crawl", "browser-actions",
    "zap-scan-url", "zap-scan-full", "zap-scan-openapi",
    "swagger-parser", "swagger-endpoints", "swagger-specs", "graphql-detect", "graphql-audit",
}


def _strip_auth(argv):
    """Drop any existing Authorization/Cookie --header pair so a fresh token can replace it."""
    out, i = [], 0
    while i < len(argv):
        a = argv[i]
        if a in ("--header", "-H") and i + 1 < len(argv) and \
                str(argv[i + 1]).lower().startswith(("authorization:", "cookie:")):
            i += 2
            continue
        out.append(a)
        i += 1
    return out


# --- scope guard: keep active calls on the target's domain (set BOB_SCOPE to widen) ---
_SCOPE_EXEMPT = {"--list", "--help", "workflow"}
_DOMAIN_ONLY = {"wayback", "wayback-domains"}   # broad archive/subdomain recon: only for a bare-domain target


def _apex(host):
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def _scope_extra():
    return [h.strip().lower() for h in os.environ.get("BOB_SCOPE", "").split(",") if h.strip()]


def _host_of(argv):
    for a in argv[1:]:
        if isinstance(a, str) and a.startswith(("http://", "https://")):
            return (urlparse(a).hostname or "").lower()
    if len(argv) > 1 and isinstance(argv[1], str) and "." in argv[1] and "/" not in argv[1] and " " not in argv[1]:
        return argv[1].split(":")[0].lower()          # bare host arg, e.g. swagger-specs example.com
    return ""


def _url_of(argv):
    return next((a for a in argv[1:] if isinstance(a, str) and a.startswith(("http://", "https://"))), "")


def _struct_sig(argv):
    """Structural signature of an active-test target: same path BASENAME + same query-param NAMES is the
    same functionality even under a different directory (…/bugs/verify.php vs …/mantis/verify.php vs
    …/verify.php). Returns None when there are no query params - too coarse to call 'same functionality'."""
    url = _url_of(argv)
    if not url:
        return None
    u = urlparse(url)
    params = frozenset(k.lower() for k, _ in parse_qsl(u.query))
    if not params:
        return None
    basename = (u.path.rstrip("/").rsplit("/", 1)[-1] or "/").lower()
    return (argv[0], (u.hostname or "").lower(), basename, params)


def _in_scope(thost, base_host, extra):
    if not thost or not base_host:
        return True
    apex = _apex(base_host)
    if thost == base_host or thost == apex or thost.endswith("." + apex):
        return True
    return any(thost == e or thost.endswith("." + e) for e in extra)

# recon/spec tools whose URL output auto-populates the shared surface, so the FULL documented/discovered
# endpoint set lands in ctx (deterministically) instead of only what a model happens to echo into artifacts.
_URL_SOURCES = {"swagger-endpoints", "katana-crawl", "js-endpoints", "wayback", "dirsearch", "dirb"}

ALLOWED = {
    "httpx", "dnsx", "wayback", "wayback-domains", "katana-crawl", "js-endpoints",
    "dirsearch", "dirb", "path-fuzz", "nuclei", "git-extract", "scan-secrets", "screenshot",
    "fuzz", "sqlmap", "zap-scan-url", "zap-scan-full", "zap-scan-openapi", "swagger-parser",
    "swagger-endpoints", "swagger-specs", "graphql-detect", "graphql-audit", "http-request",
    "browser-crawl", "browser-login", "browser-actions",
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
    # http-request has no method override - turn the cryptic argparse error into actionable guidance
    if tool == "http-request" and any(t in ("-X", "--method") for t in argv):
        return json.dumps({"success": False, "error":
            "http-request does GET (default) or POST (when you pass -D/--data) ONLY - there is no -X/--method "
            "override, so OPTIONS/TRACE/HEAD/PUT/DELETE are unsupported. Drop the -X flag."})
    # a bare `--data {FUZZ}` posts ONE payload as the entire body - a structured (JSON/form) API just 400s it
    if tool == "fuzz":
        for i, t in enumerate(argv):
            if t == "--data" and i + 1 < len(argv) and argv[i + 1].strip() in ("{FUZZ}", "{NUMBERS}"):
                return json.dumps({"success": False, "error":
                    "bare '--data {FUZZ}' sends one payload as the ENTIRE body - a structured API rejects it. "
                    "Build a real body with {FUZZ} in ONE field, e.g. --data '{\"email\":\"{FUZZ}\",\"password\":\"x\"}' "
                    "(get the field names from swagger-parser), and add --header 'Content-Type: application/json' for JSON."})
    if not aggressive:
        for i, t in enumerate(argv):
            if t in ("--method", "-X") and i + 1 < len(argv) and argv[i + 1].lower() in MUTATING:
                return json.dumps({"success": False,
                                   "error": "mutating method blocked (run bob with --aggressive to allow PUT/PATCH/DELETE)"})
    return None


class InProcessRunner:
    """`runner(argv, allowed=agent.tools)` -> JSON envelope text, dispatched in-process."""

    def __init__(self, tool_timeout=600, aggressive=False, max_calls=500):
        self.tool_timeout = tool_timeout
        self.aggressive = aggressive
        self.max_calls = max_calls
        self._calls = 0
        self._cache = {}   # argv -> output (shared across agents for the whole run)
        self._count = {}   # argv -> times requested (loop/repeat breaker)
        self._sigs = {}    # structural signature -> first URL tested (same-functionality dedupe)

    def __call__(self, argv, allowed=None, ctx=None):
        err = _check(argv, allowed, self.aggressive)
        if err:
            return err
        self._calls += 1
        if self._calls > self.max_calls:
            return json.dumps({"success": False, "error": f"run budget reached ({self.max_calls} tool calls) - stopping"})
        if ctx and getattr(ctx, "base_url", "") and argv[0] not in _SCOPE_EXEMPT:
            entry = getattr(ctx, "entry", "domain")
            if entry != "domain" and argv[0] in _DOMAIN_ONLY:
                return json.dumps({"success": False,
                                   "error": f"'{argv[0]}' (broad archive/subdomain recon) is noise for a {entry} "
                                            f"target - test the {entry} directly (swagger-parser/swagger-endpoints "
                                            f"for a spec; the given URL for an endpoint)"})
            base_host = (urlparse(ctx.base_url).hostname or "").lower()
            thost = _host_of(argv)
            extra = _scope_extra()
            ok = _in_scope(thost, base_host, extra) if entry == "domain" \
                else (not thost or thost == base_host or thost in extra)
            if not ok:
                return json.dumps({"success": False,
                                   "error": f"'{thost}' is out of scope ({entry} target {base_host}); set BOB_SCOPE to widen"})
        # same-functionality dedupe: a second active test whose path basename + query-param names match an
        # already-tested URL (…/bugs/verify.php vs …/mantis/verify.php) is the same code - skip the waste.
        if argv and argv[0] in ("fuzz", "sqlmap"):
            sig = _struct_sig(argv)
            if sig is not None:
                first = self._sigs.get(sig)
                cur = _url_of(argv)
                if first and first != cur:
                    return json.dumps({"success": False, "error":
                        f"skipped: '{cur}' is structurally identical to already-tested '{first}' (same path "
                        f"basename + same query parameters = same functionality). Test a different endpoint/param."})
                self._sigs.setdefault(sig, cur)
        argv = self._inject_auth(list(argv), ctx)
        key = tuple(argv)
        # Anti-spin is PER-AGENT (one agent repeating itself = a loop). A LATER agent re-running the same
        # call - the validator re-firing a finding's reproduce, or a re-sweep - is legitimate and must NOT be
        # refused: serve it free from the shared cache. (A global refusal was silently sabotaging the
        # validator, which then DROPPED findings it couldn't re-confirm, and made re-sweep calls no-op
        # instantly.) Cache check comes first so a repeat is always answered with the real result.
        agent = getattr(ctx, "current_agent", "") if ctx else ""
        ckey = (agent, key)
        self._count[ckey] = self._count.get(ckey, 0) + 1
        if key in self._cache:
            self._record(ctx, argv, self._cache[key], cached=True)
            return self._cache[key]
        if self._count[ckey] > 2:
            return json.dumps({"success": False, "error":
                               "this exact call already ran for this agent - reuse the earlier result and move on "
                               "(repeating it makes no progress)"})
        out = self._maybe_reauth(argv, self._dispatch(argv), ctx)
        self._cache[key] = out
        self._record(ctx, argv, out, cached=False)
        return out

    def _record(self, ctx, argv, out, cached):
        if not ctx:
            return
        try:
            env = json.loads(out)
        except Exception:  # noqa: BLE001
            env = {}
        data = env.get("data") if isinstance(env.get("data"), list) else []
        status = data[0].get("status") if data and isinstance(data[0], dict) else None
        ctx.record(argv[0], argv[1] if len(argv) > 1 else "", bool(env.get("success")),
                   env.get("kind"), len(data), status, cached)
        ctx.responses[tuple(argv)] = out
        # deterministic surface ingestion: pull every endpoint URL a recon/spec tool returned into the
        # shared surface, so later agents + the coverage sweep act on the WHOLE set (not the model's sample)
        if argv[0] in _URL_SOURCES and data:
            eps = []
            for d in data:
                u = d if isinstance(d, str) else (d.get("url") if isinstance(d, dict) else None)
                if isinstance(u, str) and u.startswith(("http://", "https://")):
                    eps.append(u)
            if eps:
                ctx.add_surface("param_urls", [u for u in eps if "?" in u])
                ctx.add_surface("endpoints", [u for u in eps if "?" not in u])
        if not getattr(ctx, "baseline", "") and argv[0] == "http-request" and len(argv) > 1 \
                and str(argv[1]).rstrip("/") == (ctx.base_url or "").rstrip("/") and data and isinstance(data[0], dict):
            ctx.baseline = str(data[0].get("content") or "")[:8000]

    def _dispatch(self, argv):
        from ..cli import main as cli_main  # deferred: avoids a circular import at module load
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                cli_main(list(argv))
        except SystemExit:
            pass
        except Exception as exc:  # noqa: BLE001 - a tool blowing up must not kill the pipeline
            return json.dumps({"success": False, "error": f"{argv[0]} failed: {exc}"})
        raw = buf.getvalue().strip()
        return _truncate(raw) if raw else json.dumps({"success": True, "data": [], "error": None})

    def _inject_auth(self, argv, ctx):
        """Append the active managed session's token to an app-targeted, header-capable call."""
        if not ctx or not argv or argv[0] not in _HEADER_TOOLS:
            return argv
        sess = ctx.active_session()
        if not sess or not sess.access:
            return argv
        host = urlparse(ctx.base_url).hostname if ctx.base_url else None
        target = next((a for a in argv if isinstance(a, str) and a.startswith(("http://", "https://"))), "")
        if not host or not target or urlparse(target).hostname != host:
            return argv
        if any(isinstance(a, str) and a.lower().startswith(("authorization:", "cookie:")) for a in argv):
            return argv                       # caller set an explicit identity - respect it
        header = sess.auth_header()
        return argv + ["--header", header] if header else argv

    def _maybe_reauth(self, argv, out, ctx):
        """If an app http-request came back 401/403, refresh the session and retry once."""
        if not ctx or not argv or argv[0] != "http-request":
            return out
        from . import session as S
        if not S.is_unauthorized(out):
            return out
        sess = ctx.active_session()
        if not sess or not (sess.refresh or sess.creds):
            return out
        if S.refresh(sess, self):             # refresh drives http-request through this same runner
            ctx.sync_identity(sess)
            return self._dispatch(self._inject_auth(_strip_auth(argv), ctx))
        return out

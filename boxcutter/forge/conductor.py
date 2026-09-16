"""boxcutter forge - a local, web-only bug-bounty conductor.

Give it a domain or a URL. It maps the web assets, then drives boxcutter's RAW
tools against each - it does NOT run the canned YAML workflows and does NOT call
bob/caleb. A pluggable ORCA (a console agent CLI, or LiteLLM / any provider)
plans which tools to run next from the live observations; the conductor executes
them, captures findings, and reports. Web only: no smart contracts, no infra,
no source.

The conductor is deterministic (map, run tools, capture, report); the model is
consulted only at the judgment points, in vera's vocabulary (rank_assets, plan,
triage). Every plan and every tool call is appended to an always-on run log. When
no orca is available (--mock / no key), a deterministic default plan runs instead,
so forge always produces findings.

  boxcutter forge example.com                       # console agent, whole domain
  boxcutter forge example.com --orca claude-code    # internal, authenticated Claude Code CLI (no API key)
  boxcutter forge https://app.example.com --mock    # offline default plan, one site
  boxcutter forge example.com --provider litellm --model openai/gpt-5
  boxcutter forge example.com --orca-cmd "codex exec --model {model} {prompt}"

  export BOXCUTTER_FORGE_ORCA=claude-code           # preconfigure the backend once (then no flag)
  boxcutter forge example.com
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from ..core import scope as _scope
from ..core.args import add_severity_arg
from ..core.envelope import (
    output_result,
    set_json_file,
    set_jsonl_file,
    set_output_kind,
    set_severity_filter,
    set_table_mode,
)
from ..tools.registry import BY_NAME
from ..workflows._common import (
    add_header_option,
    add_overrides_option,
    add_scope_option,
    add_steps_option,
    call,
    finding,
)
from ..workflows.filters import FILTERS, PARAM_FILTERS
from ..ai import skills as _skills
from . import report as _rpt
from . import identity as _idn
from .orca import add_orca_args, resolve_orca

NAME = "forge"
KIND = "findings"
HELP = "Web-only bug-bounty conductor: map assets, drive boxcutter's raw tools, triage (orca), report."

# The raw boxcutter tools the orca may plan (web-focused, read-only-ish). Deliberately
# excludes the agent tools (bob/caleb/travis/irvin/vera) and the ZAP active scanners.
_DISCOVERY_TOOLS = [
    "ping-scan", "nmap", "httpx", "katana-crawl", "harvest", "js-endpoints", "wayback",
    "smart-enum", "swagger-specs", "swagger-endpoints", "graphql-detect", "http-request",
]
_TEST_TOOLS = [
    "fuzz", "sqlmap", "nuclei", "path-fuzz", "path-bust", "dirsearch", "api-map",
    "graphql-audit", "scan-secrets", "blind-oracle", "bola-walk", "mass-assign",
    "git-extract",
]
_TOOLS = _DISCOVERY_TOOLS + _TEST_TOOLS

_MAX_TARGETS = 25          # cap per-round fan-out over discovered URLs (default plan)
_W = 64

# The 7-Question Gate (bountyforge) - the orca answers these per finding and returns a
# verdict. confirmed / open_proof_gap are reported; ruled_out is dropped.
_GATE_QUESTIONS = [
    "In scope for this target?",
    "Does it cross a real security boundary (not intended behaviour)?",
    "Can an unprivileged / reachable actor trigger it?",
    "Is there concrete impact to an identifiable victim?",
    "Not a false positive (soft-404, reflected-not-executed, self-XSS, CSRF-token field)?",
    "Is there evidence (a captured request/response), not just a claim?",
    "Not a duplicate of another finding?",
]


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target", help="A domain (enumerated to hosts) or a URL/host (scanned as-is).")
    parser.add_argument("--max-assets", type=int, default=8, metavar="N",
                        help="Scan at most N mapped hosts (default 8).")
    parser.add_argument("--max-rounds", type=int, default=2, metavar="N",
                        help="Plan/execute rounds per asset: round 0 discovers, later rounds test (default 2).")
    parser.add_argument("--no-recon", action="store_true",
                        help="Skip subdomain enumeration; scan the target host only.")
    parser.add_argument("--out-dir", default=None, metavar="DIR",
                        help="Write the run log + report here (default: forge_<host>_<ts>/).")
    parser.add_argument("--report-format", dest="report_format", default="generic",
                        choices=["h1", "bugcrowd", "intigriti", "immunefi", "generic"],
                        help="Report template for the written REPORT.md (default generic).")
    parser.add_argument("--creds", default=None, metavar="USER:PASS",
                        help="Log in via a real browser with these credentials (identity A) and hunt authenticated.")
    parser.add_argument("--creds-b", dest="creds_b", default=None, metavar="USER:PASS",
                        help="A second identity, for differential BOLA/BFLA tests (bola-walk -A/-B).")
    parser.add_argument("--login-url", dest="login_url", default=None, metavar="URL",
                        help="Login page URL for --creds (default: the target).")
    add_orca_args(parser)           # --provider/--model/--api-key/--llm-proxy-url/--orca-cmd/--mock
    add_scope_option(parser)        # --scope / --no-scope
    add_header_option(parser)       # --header (propagated to every tool that supports it)
    add_steps_option(parser)        # --steps
    add_overrides_option(parser)    # --arg TOOL="..."
    add_severity_arg(parser)        # --severity
    parser.add_argument("--output", default=None, metavar="FILE", help="Save findings to FILE (default stdout).")
    parser.add_argument("--json", dest="json", default=None, metavar="FILE", help="Also save the JSON envelope to FILE.")
    parser.add_argument("--jsonl", default=None, metavar="FILE", help="Also save findings as JSON Lines to FILE.")
    parser.add_argument("--table", action="store_true", help="Render findings as a table on stdout.")
    parser.add_argument("--debug", action="store_true", help="Print diagnostics to stderr.")


def _phase(title: str) -> None:
    sys.stderr.write(f"\n{'-' * _W}\n  {title}\n{'-' * _W}\n")
    sys.stderr.flush()


def _line(msg: str) -> None:
    sys.stderr.write(f"  {msg}\n")
    sys.stderr.flush()


def _with_scheme(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return ""
    return host if host.startswith(("http://", "https://")) else "https://" + host


def _catalog() -> list[dict]:
    out = []
    for name in _TOOLS:
        mod = BY_NAME.get(name)
        if mod is not None:
            out.append({"tool": name, "kind": getattr(mod, "KIND", "items"),
                        "help": (getattr(mod, "HELP", "") or "").split("\n")[0][:90]})
    return out


def _orca(orca, log, task: str, context: dict, schema_hint: str = "") -> dict:
    """One judgment call, logged. Never raises: a failure returns {} so the
    conductor falls back to its deterministic default."""
    try:
        out = orca.decide(task, context, schema_hint=schema_hint)
    except Exception as exc:  # noqa: BLE001 - the orca must never abort the run
        out = {"_error": str(exc)}
    if not isinstance(out, dict):
        out = {"value": out}
    log.append({"t": time.time(), "kind": "orca", "task": task, "reply": out})
    return out


# --- asset mapping (raw recon tools, not the recon workflow) ------------------

def _alive(hosts: list[str], args) -> list[str]:
    """Keep the hosts that resolve, via the dnsx tool (dnsx prints a line starting
    with the host name when it resolves)."""
    dnsx = BY_NAME.get("dnsx")
    if dnsx is None:
        return hosts
    keep = []
    for h in hosts:
        lines = call(dnsx, [h], args) or []
        if any(isinstance(x, str) and x.startswith(h) for x in lines):
            keep.append(h)
    return keep


_IP_RANGE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2}|-\d{1,3}(?:\.\d{1,3}){0,3})?$")


def _looks_like_range(target: str) -> bool:
    """A bare IP, CIDR (10.0.0.0/24), or nmap range (10.0.0.1-50) - an nmap target."""
    return bool(_IP_RANGE.match(target.strip()))


def _map_assets(args, log) -> tuple:
    """Return (web_asset_urls, endpoints). A domain is enumerated to hosts; a URL is
    scanned as-is; an IP/CIDR/range is nmap-scanned, its web ports become assets and
    every open port is recorded as an endpoint (IP/PORT/VERSION)."""
    _phase("MAP - discover web assets")
    target = args.target.strip()
    endpoints: list[dict] = []
    if urlparse(target).scheme:                       # a URL/host: scan as-is
        assets = [target]
    elif _looks_like_range(target):                   # an IP / CIDR / range: nmap it
        nmap = BY_NAME.get("nmap")
        endpoints = [e for e in (call(nmap, [target], args) or []) if isinstance(e, dict)] if nmap else []
        _line(f"nmap: {len(endpoints)} open port(s)")
        web = [e["url"] for e in endpoints if e.get("url")]
        if web:
            assets = web
        elif "/" not in target and "-" not in target:  # a single IP -> try it as a web asset
            assets = [_with_scheme(target)]
        else:
            assets = []                               # a range with no web port -> report endpoints only
    elif args.no_recon:
        assets = [_with_scheme(target)]
    else:                                             # a bare domain: subfinder -> alive
        subfinder = BY_NAME.get("subfinder")
        hosts = (call(subfinder, [target], args) or []) if subfinder else []
        hosts = list(dict.fromkeys([target] + [h for h in hosts if isinstance(h, str) and h]))
        _line(f"subfinder: {len(hosts)} host(s); resolving ...")
        alive = _alive(hosts, args)
        assets = [_with_scheme(h) for h in alive] or [_with_scheme(target)]
    assets = list(dict.fromkeys(a for a in assets if a))[:500]   # bound; top-N picked after prioritize
    log.append({"t": time.time(), "kind": "map", "assets": assets, "endpoints": len(endpoints)})
    _line(f"{len(assets)} asset(s): " + ", ".join(assets[:6]) + (" ..." if len(assets) > 6 else ""))
    return assets, endpoints


# hostname keyword -> interest weight. A deterministic first estimate of how much a
# host is worth hunting; the orca may then reorder. (boxcutter's travis does a live
# version; this is the cheap, no-probe estimate.)
_HOT = {
    "api": 40, "graphql": 30, "admin": 40, "internal": 35, "intranet": 35, "staging": 30,
    "stage": 30, "dev": 30, "test": 25, "qa": 25, "uat": 25, "auth": 30, "sso": 30,
    "login": 25, "account": 25, "accounts": 25, "vpn": 25, "jenkins": 35, "grafana": 30,
    "gitlab": 30, "git": 25, "payment": 35, "pay": 30, "billing": 30, "dashboard": 25,
    "portal": 20, "beta": 20, "secure": 20, "internal-api": 45, "my": 15, "app": 15,
}


def _estimate_score(host: str) -> tuple[int, list[str]]:
    h = (urlparse(host).hostname or host).lower()
    hits = [p for p in re.split(r"[.\-_]", h) if p in _HOT]
    return 10 + sum(_HOT[p] for p in hits), hits


def _prioritize(args, orca, log, assets: list[str]) -> tuple[list[str], dict]:
    """Estimate each asset's value (deterministic hostname score), then let the orca
    reorder. Returns the ordered assets and an asset->score map for the model."""
    scored = sorted(((a, *_estimate_score(a)) for a in assets), key=lambda x: x[1], reverse=True)
    order = [a for a, _, _ in scored]
    scores = {a: s for a, s, _ in scored}
    est = [{"asset": a, "score": s, "signals": h} for a, s, h in scored]
    log.append({"t": time.time(), "kind": "estimate", "top": est[:20]})
    if len(order) > 1:
        _phase("PRIORITIZE - estimate + order the surface")
        reply = _orca(orca, log, "prioritize", {"estimates": est},
                      schema_hint='{"ranked": ["<url>", ...]}  most valuable first (may reorder the estimate)')
        ranked = [a for a in reply.get("ranked", []) if a in assets]
        order = ranked + [a for a in order if a not in ranked] if ranked else order
        _line("top: " + ", ".join(f"{a} ({scores[a]})" for a in order[:6]))
    return order, scores


def _probe(url: str, id_headers: list[str], args) -> tuple | None:
    """GET `url` (optionally as an identity, via -H) and return (status, body_len).
    None if the http-request tool is missing or the probe failed."""
    hr = BY_NAME.get("http-request")
    if hr is None:
        return None
    argv = [url]
    for h in id_headers:
        argv += ["-H", h]
    data = call(hr, argv, args) or []
    it = data[0] if data and isinstance(data[0], dict) else None
    if not it or it.get("status") is None:
        return None
    return int(it["status"]), len(str(it.get("content") or ""))


def _differs(anon: tuple | None, authed: tuple | None) -> bool:
    """True when the authed response materially differs from anon - the proof that a
    session actually changed access (Vera's differential gate)."""
    if not anon or not authed:
        return False
    a_status, a_len = anon
    b_status, b_len = authed
    if a_status != b_status:                          # e.g. anon 401/302 -> authed 200
        return True
    return abs(b_len - a_len) > max(256, int(0.05 * max(a_len, 1)))


def _prove(ident, args, log) -> bool:
    """Prove the identity is live by a differential probe: request a page as the
    identity and as anon and compare. Sets `alive`. If the probe cannot run (no
    http-request tool / network), fall back to trusting the captured session."""
    probe_url = getattr(args, "login_url", None) or _with_scheme(args.target)
    anon = _probe(probe_url, [], args)
    authed = _probe(probe_url, ident.headers(), args)
    if anon is None and authed is None:
        verified = False
        ident.alive = bool(ident.cookie or ident.token)   # unverifiable -> trust capture
    else:
        verified = True
        ident.alive = _differs(anon, authed)
    log.append({"t": time.time(), "kind": "auth_proof", "identity": ident.label,
                "verified": verified, "alive": ident.alive, "anon": anon, "authed": authed})
    _line(f"  {ident.label} proof: {'verified alive' if (verified and ident.alive) else ('refuted' if verified else 'unverified, trusting capture')}")
    return ident.alive


def _login_identity(login, login_url: str, creds: str, label: str, args, log):
    if not creds:
        return None
    data = call(login, [login_url, "--creds", creds], args) or []
    item = data[0] if data and isinstance(data[0], dict) else {}
    ident = _idn.from_login_item(label, item)
    log.append({"t": time.time(), "kind": "auth", "identity": label,
                "cookie": bool(ident.cookie), "token": bool(ident.token)})
    _line(ident.masked())
    if not (ident.cookie or ident.token):
        return None
    return ident if _prove(ident, args, log) else None


def _authenticate(args, log) -> tuple:
    """Log in via a real browser (browser-login) and PROVE each session by a
    differential probe. Returns (identity_A, identity_B); a refuted login is
    dropped, never assumed. Identity A's headers are threaded into every tool call."""
    if not getattr(args, "creds", None):
        return None, None
    login = BY_NAME.get("browser-login")
    if login is None:
        _line("browser-login unavailable; continuing anonymous")
        return None, None
    _phase("AUTH - browser login + differential proof")
    login_url = getattr(args, "login_url", None) or _with_scheme(args.target)
    return (_login_identity(login, login_url, args.creds, "A", args, log),
            _login_identity(login, login_url, getattr(args, "creds_b", None), "B", args, log))


def _thread_identity(args) -> None:
    """Set args.header = the user's headers + identity A's session headers, so every
    header-capable tool call runs authenticated. Idempotent (rebuilt from the stored
    user headers), so it is safe to call again after a re-auth."""
    base = list(getattr(args, "_user_headers", None) or [])
    ida = getattr(args, "_id_a", None)
    args.header = base + (ida.headers() if ida else [])


def _ensure_alive(args, log) -> None:
    """Re-auth on expiry: if identity A no longer proves alive and a re-auth budget
    remains, log in once more and re-thread. Bounded by args._reauth_left."""
    ida = getattr(args, "_id_a", None)
    if not ida or getattr(args, "_reauth_left", 0) <= 0:
        return
    if _prove(ida, args, log):                        # still good
        return
    login = BY_NAME.get("browser-login")
    if login is None or not getattr(args, "creds", None):
        return
    args._reauth_left -= 1
    _line("  identity A went stale - re-authenticating")
    fresh = _login_identity(login, getattr(args, "login_url", None) or _with_scheme(args.target),
                            args.creds, "A", args, log)
    if fresh:
        args._id_a = fresh
        _thread_identity(args)


# --- the per-asset tool loop --------------------------------------------------

def _new_obs() -> dict:
    return {"urls": [], "gql": [], "specs": [], "tech": []}


def _absorb(obs: dict, tool: str, data: list, bases: list) -> int:
    """Fold a discovery tool's output into the observations. Returns the number of
    NEW in-scope URLs learned, so the loop can stop when a round adds nothing."""
    urls = FILTERS["urls"]([d for d in data if isinstance(d, (str, dict))])
    if bases:
        urls = [u for u in urls if _scope.in_scope(u, bases)]
    bucket = {"graphql-detect": "gql", "swagger-specs": "specs"}.get(tool, "urls")
    seen = set(obs[bucket])
    learned = 0
    for u in urls:
        if u not in seen:
            obs[bucket].append(u)
            seen.add(u)
            learned += 1
    return learned if bucket == "urls" else 0


def _obs_summary(obs: dict) -> dict:
    return {"url_count": len(obs["urls"]),
            "param_urls": FILTERS["params"](obs["urls"])[:40],
            "js_urls": FILTERS["js"](obs["urls"])[:40],
            "graphql": obs["gql"][:10], "swagger_specs": obs["specs"][:10]}


def _default_actions(round_i: int, asset: str, obs: dict) -> list[dict]:
    """Deterministic fallback plan when no orca answers: round 0 discovers, later
    rounds test each discovered surface."""
    if round_i == 0:
        return [{"tool": t, "target": asset} for t in
                ("httpx", "katana-crawl", "swagger-specs", "graphql-detect")]
    acts: list[dict] = []
    for u in FILTERS["params"](obs["urls"])[:_MAX_TARGETS]:
        acts.append({"tool": "fuzz", "target": u, "args": "--timeout 120"})
        acts.append({"tool": "nuclei", "target": u, "args": "--opt-args=-dast"})
    for u in FILTERS["js"](obs["urls"])[:_MAX_TARGETS]:
        acts.append({"tool": "scan-secrets", "target": u})
    for g in obs["gql"][:5]:
        acts.append({"tool": "graphql-audit", "target": g})
    return acts


# skill playbook -> the forge tool(s) that exercise that class. A playbook loads ONLY
# when its surface is observed AND a covering tool is in the catalog, so the loaded
# knowledge stays web-only and matched to what forge can actually TEST.
_SKILL_TOOLS = {
    "sqli": ("fuzz", "sqlmap"), "xss": ("fuzz",), "ssti": ("fuzz",), "lfi": ("fuzz",),
    "xxe": ("fuzz",), "rce": ("fuzz",), "nosql": ("fuzz",), "idor": ("bola-walk",),
    "graphql": ("graphql-audit", "graphql-detect"),
    "swagger": ("swagger-endpoints", "swagger-specs"),
    "secrets": ("scan-secrets",), "info_disclosure": ("scan-secrets", "git-extract"),
}


def _signals(obs: dict) -> list[str]:
    """Surface signals -> boxcutter skill names, kept to WEB classes a forge tool can
    exercise (per _SKILL_TOOLS). Deterministic and signal-gated, so the same target
    loads the same playbooks; a class no tool can test is never loaded."""
    want: set[str] = set()
    if FILTERS["params"](obs["urls"]):
        want |= {"sqli", "xss", "ssti", "lfi", "xxe", "rce", "nosql", "idor"}
    if FILTERS["js"](obs["urls"]):
        want |= {"secrets", "info_disclosure"}
    if obs["gql"]:
        want.add("graphql")
    if obs["specs"]:
        want.add("swagger")
    return sorted(s for s in want if any(t in _TOOLS for t in _SKILL_TOOLS.get(s, ())))


# a path segment that looks like an object id (numeric or uuid) - a BOLA candidate
# even without a query param, e.g. /api/orders/1042 or /users/<uuid>.
_ID_SEG = re.compile(r"/(?:\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)", re.I)


def _id_urls(urls: list[str]) -> list[str]:
    return [u for u in urls if _ID_SEG.search(urlparse(u).path or "")]


def _core_actions(obs: dict) -> list[dict]:
    """The always-on CORE floor (bountyforge's ever-present core): every test round
    fuzzes each param URL and scans each JS file for secrets, whatever the orca planned."""
    acts = [{"tool": "fuzz", "target": u, "args": "--timeout 120"}
            for u in FILTERS["params"](obs["urls"])[:_MAX_TARGETS]]
    acts += [{"tool": "scan-secrets", "target": u} for u in FILTERS["js"](obs["urls"])[:_MAX_TARGETS]]
    return acts


def _merge_actions(primary: list[dict], floor: list[dict]) -> list[dict]:
    seen = {(a.get("tool"), a.get("target")) for a in primary}
    out = list(primary)
    for a in floor:
        key = (a.get("tool"), a.get("target"))
        if key not in seen:
            out.append(a)
            seen.add(key)
    return out


def _plan(args, orca, log, asset: str, obs: dict, round_i: int) -> list[dict]:
    signals = _signals(obs)
    if signals:
        log.append({"t": time.time(), "kind": "playbooks", "asset": asset, "round": round_i, "loaded": signals})
    context = {"asset": asset, "round": round_i, "observations": _obs_summary(obs),
               "tools": _catalog(), "skill_catalog": _skills.catalog()}
    playbooks = _skills.for_signals(signals)
    if playbooks:
        context["playbooks"] = playbooks               # web + tool-backed methodology, loaded on signal
    reply = _orca(orca, log, "plan", context,
                  schema_hint='{"actions": [{"tool": "<name from tools>", "target": "<url>", '
                              '"args": "<optional cli flags>", "why": "..."}]}')
    actions = [a for a in reply.get("actions", []) if isinstance(a, dict) and a.get("tool") in _TOOLS]
    return actions or _default_actions(round_i, asset, obs)


def _run_tool(name: str, target: str, extra: str, args, log, findings: list, obs: dict, bases: list, asset: str = "") -> list:
    mod = BY_NAME.get(name)
    if mod is None or not target:
        return []
    _line(f"{name} {target}")
    argv = [target, *shlex.split(extra or "")]
    if name == "bola-walk":                           # two-session diff: pass identity A/B headers
        for h in (getattr(args, "_id_a", None).headers() if getattr(args, "_id_a", None) else []):
            argv += ["-A", h]
        for h in (getattr(args, "_id_b", None).headers() if getattr(args, "_id_b", None) else []):
            argv += ["-B", h]
    data = call(mod, argv, args) or []
    new_findings: list = []
    if getattr(mod, "KIND", "items") == "findings":
        url = target if target.startswith("http") else None
        for it in data:
            if isinstance(it, dict):
                f = finding(name, it, url)
                f["asset"] = asset                    # provenance: which asset produced it
                if not bases or _scope.in_scope(f.get("url") or url, bases):
                    findings.append(f)
                    new_findings.append(f)
        log.append({"t": time.time(), "kind": "tool", "tool": name, "target": target,
                    "findings": len(new_findings)})
    else:
        learned = _absorb(obs, name, data, bases)
        if name == "httpx":                           # passive fingerprint into the model
            for it in data:
                if isinstance(it, dict):
                    for key in ("tech", "webserver", "title"):
                        val = it.get(key)
                        for t in (val if isinstance(val, list) else [val]):
                            if isinstance(t, str) and t and t not in obs["tech"]:
                                obs["tech"].append(t)
        log.append({"t": time.time(), "kind": "tool", "tool": name, "target": target,
                    "learned_urls": learned})
    return new_findings


def _run_asset(args, orca, log, asset: str, bases: list) -> tuple:
    findings: list[dict] = []
    obs = _new_obs()
    for round_i in range(max(1, args.max_rounds)):
        actions = _plan(args, orca, log, asset, obs, round_i)
        if round_i > 0:                               # CORE floor: always test params + JS secrets
            actions = _merge_actions(actions, _core_actions(obs))
            if getattr(args, "_id_b", None):          # two identities -> differential BOLA/BFLA
                targets = list(dict.fromkeys(FILTERS["params"](obs["urls"]) + _id_urls(obs["urls"])))
                actions = _merge_actions(actions, [{"tool": "bola-walk", "target": u}
                                                    for u in targets[:_MAX_TARGETS]])
        if not actions:
            break
        before_urls = len(obs["urls"])
        queue = list(actions)
        sqlmapped: set[str] = set()
        for act in queue:
            tool = act.get("tool")
            tgt = act.get("target") or asset
            if tool not in _TOOLS:
                continue
            new_f = _run_tool(tool, tgt, act.get("args", ""), args, log, findings, obs, bases, asset)
            # Double-confirm SQLi: a fuzz sqli lead triggers sqlmap on the SAME target,
            # and the fuzz sqli finding is dropped so only sqlmap's verdict is reported.
            if tool == "fuzz" and tgt not in sqlmapped and PARAM_FILTERS["class"]("sql", new_f):
                sqlmapped.add(tgt)
                drop = {id(f) for f in PARAM_FILTERS["class"]("sql", new_f)}
                findings[:] = [f for f in findings if id(f) not in drop]
                queue.append({"tool": "sqlmap", "target": tgt})
        if round_i > 0 and len(obs["urls"]) == before_urls:
            break                                     # a test round learned no new surface -> stop
    entry = {"asset": asset, "url_count": len(obs["urls"]),
             "param_urls": FILTERS["params"](obs["urls"]), "js_urls": FILTERS["js"](obs["urls"]),
             "graphql": obs["gql"], "swagger_specs": obs["specs"], "tech": obs.get("tech", [])}
    return findings, entry


def _chain(args, orca, log, findings: list[dict]) -> list[dict]:
    """Compose confirmed findings into A->B->C chains via the orca (bountyforge's
    kill_chain). Deterministic fallback: no chains."""
    if len(findings) < 2:
        return []
    _phase("CHAIN - compose findings")
    reply = _orca(orca, log, "chain", {"findings": findings},
                  schema_hint='{"chains": [{"name": "...", "severity": "...", '
                              '"steps": ["<finding title>", ...], "why": "..."}]}')
    chains = reply.get("chains")
    chains = chains if isinstance(chains, list) and all(isinstance(c, dict) for c in chains) else []
    _line(f"{len(chains)} chain(s)")
    return chains


def _gate(args, orca, log, findings: list[dict]) -> list[dict]:
    """The 7-Question Gate: the orca judges each finding and returns a verdict of
    confirmed / open_proof_gap / ruled_out. ruled_out is dropped; the rest are kept
    and tagged with their verdict. Deterministic fallback: keep all as open_proof_gap
    (unproven, but never silently dropped)."""
    if not findings:
        return findings
    _phase("GATE - 7-question triage")
    reply = _orca(orca, log, "gate", {"findings": findings, "questions": _GATE_QUESTIONS},
                  schema_hint='{"verdicts": [{"title": "<finding title>", '
                              '"verdict": "confirmed|open_proof_gap|ruled_out", "reason": "..."}]}')
    verdicts = reply.get("verdicts")
    by_title: dict = {}
    if isinstance(verdicts, list):
        for v in verdicts:
            if isinstance(v, dict) and v.get("title"):
                by_title[v["title"]] = v
    kept: list[dict] = []
    for f in findings:
        v = by_title.get(f.get("title")) or {}
        verdict = v.get("verdict", "open_proof_gap")
        if verdict == "ruled_out":
            continue
        f["verdict"] = verdict
        f["verdict_reason"] = v.get("reason", "no orca verdict; kept unproven")
        kept.append(f)
    _line(f"kept {len(kept)} / {len(findings)} (ruled_out dropped)")
    return kept


def _report(args, log, findings: list[dict], chains: list[dict] | None = None,
            model: dict | None = None) -> None:
    _rpt.enrich(findings)                             # tag each finding with class / CWE / CVSS
    host = urlparse(_with_scheme(args.target)).hostname or "target"
    model = model or {"assets": []}
    out_dir = Path(args.out_dir) if args.out_dir else Path(f"forge_{host}_{int(time.time())}")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "run.jsonl").write_text(
            "\n".join(json.dumps(e, ensure_ascii=False, default=str) for e in log) + "\n", encoding="utf-8")
        (out_dir / "model.json").write_text(json.dumps(model, ensure_ascii=False, indent=2), encoding="utf-8")
        loaded = sorted({s for e in log if e.get("kind") == "playbooks" for s in e.get("loaded", [])})
        doc = _rpt.render(host, model, findings, chains or [], loaded,
                          getattr(args, "report_format", "generic"))
        (out_dir / "REPORT.md").write_text(doc, encoding="utf-8")
        _line(f"model + report -> {out_dir}/ (REPORT.md, model.json, run.jsonl)")
    except OSError as exc:
        _line(f"(could not write report dir: {exc})")
    output_result(findings, args.output)


def _scope_bases(args) -> list:
    if getattr(args, "no_scope", False):
        return []
    explicit = getattr(args, "scope", None)
    if explicit:
        return [h for h in (_scope.host_of(d) for d in str(explicit).split(",")) if h]
    return _scope.scope_bases(args.target)


def run(args) -> int:
    set_table_mode(getattr(args, "table", False))
    set_jsonl_file(getattr(args, "jsonl", None))
    set_json_file(getattr(args, "json", None))
    set_output_kind("findings")
    set_severity_filter(getattr(args, "severity", None))

    orca = resolve_orca(args)
    reason = getattr(orca, "reason", "")
    _line(f"orca backend: {orca.name}" + (f"  ({reason})" if reason else ""))
    bases = _scope_bases(args)
    log: list[dict] = [{"t": time.time(), "kind": "start", "target": args.target, "orca": orca.name}]

    # identity/session layer: log in via a real browser, then thread identity A into
    # every header-capable tool call so the whole hunt runs authenticated.
    args._user_headers = list(getattr(args, "header", []) or [])
    args._reauth_left = 1
    id_a, id_b = _authenticate(args, log)
    args._id_a, args._id_b = id_a, id_b
    _thread_identity(args)                              # hunt authenticated as identity A

    mapped, endpoints = _map_assets(args, log)
    ordered, scores = _prioritize(args, orca, log, mapped)
    assets = ordered[: max(1, args.max_assets)]         # hunt the top-N most promising

    _phase("RUN - drive raw tools per asset")
    findings: list[dict] = []
    model: dict = {"identities": [i.label for i in (id_a, id_b) if i],
                   "endpoints": endpoints[:200], "assets": []}
    for asset in assets:
        _ensure_alive(args, log)                        # re-auth if the session expired
        fs, entry = _run_asset(args, orca, log, asset, bases)
        entry["score"] = scores.get(asset)
        findings.extend(fs)
        model["assets"].append(entry)
    log.append({"t": time.time(), "kind": "model", "assets": len(model["assets"])})
    _line(f"{len(findings)} raw finding(s) across {len(assets)} asset(s)")

    findings = _gate(args, orca, log, findings)
    chains = _chain(args, orca, log, findings)
    _report(args, log, findings, chains, model)
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="boxcutter forge", description=HELP)
    add_arguments(parser)
    return run(parser.parse_args(argv))

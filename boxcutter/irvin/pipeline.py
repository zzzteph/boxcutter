"""The irvin CONDUCTOR - a lean, fixed pipeline over the proven agents travis, bob and caleb. No council.

    RECON        travis discovers and ranks the live hosts
    SCAN         per top host: bob (fast surface pass), then caleb (deep authenticated pass) when it's worth it
    VERIFY       independent existence re-check of every aggregated finding (drops proven-absent pages)
    CONSOLIDATE  collapse provably-identical findings into one
    REPORT       a CEO executive summary + the technical findings table

Deterministic and auditable: the SAME agents in the SAME order every run - no suggester council, no
runtime-spawned agents. Every agent's reasoning (native thinking + the one-line narration) streams live and is
captured per-agent through the shared provider sink, so a run can be replayed decision by decision.

The three agents are driven IN-PROCESS via the CLI (the same in-process dispatch caleb already uses to run
bob), and their findings are folded into one landscape through Context.add_finding, so the proven VERIFY and
CONSOLIDATE gates and the REPORTER all operate exactly as before.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from urllib.parse import urlparse

from ..ai import provider as _prov
from .agents.control import Consolidator, Reporter, Verifier

_W = 64
_TIER_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _phase(title: str) -> None:
    sys.stderr.write(f"\n{'-' * _W}\n  {title}\n{'-' * _W}\n")


def _line(msg: str) -> None:
    sys.stderr.write(f"  {msg}\n")


def _cli_capture(argv: list) -> dict:
    """Run a boxcutter sub-command IN-PROCESS and return its parsed stdout JSON envelope. The agent's
    reasoning/narration still streams to the real stderr (so you watch it live); only its stdout envelope is
    captured here. A sub-agent crash becomes an error envelope - it never aborts the conductor."""
    from ..cli import main as cli_main
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            cli_main(list(argv))
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": f"{' '.join(map(str, argv[:2]))} failed: {exc}", "data": []}
    raw = buf.getvalue().strip()
    if not raw:
        return {"success": False, "error": "no output", "data": []}
    try:
        env = json.loads(raw)
    except Exception:  # noqa: BLE001
        return {"success": False, "error": "unparseable envelope", "data": [], "raw": raw[:200]}
    return env if isinstance(env, dict) else {"success": False, "error": "non-dict envelope", "data": []}


def _common_argv(opts: dict) -> list:
    """The shared LLM/auth flags forwarded to every sub-agent, so travis/bob/caleb all speak to the same
    provider with the same auth. --api-key is only forwarded when the operator passed one explicitly; otherwise
    the sub-agent reads the same provider env var this process has."""
    argv = ["--provider", opts["provider"]]
    if opts.get("model"):
        argv += ["--model", opts["model"]]
    if opts.get("api_key"):
        argv += ["--api-key", opts["api_key"]]
    if opts.get("base_url"):
        argv += ["--llm-proxy-url", opts["base_url"]]
    if opts.get("context"):
        argv += ["--context", opts["context"]]
    for h in opts.get("headers") or []:
        argv += ["--header", h]
    return argv


def _host_tier(h: dict) -> str:
    return str(h.get("interest") or h.get("class") or "low").lower()


def _host_url(h: dict) -> str:
    url = (h.get("url") or "").strip()
    if url.startswith(("http://", "https://")):
        return url
    host = (h.get("host") or "").strip()
    return "https://" + host if host else ""


def _worth_deep(tier: str, bob_env: dict) -> bool:
    """Caleb (the expensive deep pass) runs when the host is Critical, or when bob's fast pass already surfaced
    something worth chaining. A High host bob found nothing on is left at bob's pass."""
    return tier == "critical" or bool(bob_env.get("data"))


def run(provider, ctx, runner, opts) -> str:
    """Drive the fixed travis -> bob -> caleb pipeline over ctx.target, aggregate + verify + consolidate the
    findings, and return the final report (also printed to stdout)."""
    common = _common_argv(opts)
    tiers = {t.lower() for t in (opts.get("tiers") or ("critical", "high"))}
    max_hosts = int(opts.get("max_hosts", 6) or 6)
    do_deep = bool(opts.get("deep", True))
    triage_top = int(opts.get("triage_top", 15) or 15)
    domain = ctx.target
    explicit = [u for u in (opts.get("hosts") or []) if u]

    if explicit:
        # -- RECON skipped: the operator handed us the exact hosts to scan ----------------------------
        _phase("RECON  (skipped - explicit host list)")
        targets = [{"url": u, "host": (urlparse(u).hostname or ""), "interest": "high", "explicit": True}
                   for u in explicit][:max_hosts]
        _line(f"{len(targets)} host(s) provided; travis discovery skipped")
        ctx.add_record("recon", "operator", "operator", "result",
                       summary=f"{len(targets)} explicit host(s), discovery skipped",
                       data={"hosts": targets})
    else:
        # -- RECON: travis discovers + ranks the live hosts ------------------------------------------
        _phase("RECON  (travis: discover + rank live hosts)")
        _prov.reasoning_label("travis")
        recon = _cli_capture(["ai", "travis", domain, "--discover", "--triage-top", str(triage_top)] + common)
        hosts = [h for h in (recon.get("data") or []) if isinstance(h, dict)]
        hosts.sort(key=lambda h: -_TIER_RANK.get(_host_tier(h), 1))
        if recon.get("error"):
            _line(f"travis: {recon['error']}")
        _line(f"{len(hosts)} live host(s)" +
              ("; tiers: " + ", ".join(sorted({_host_tier(h) for h in hosts})) if hosts else " returned"))
        ctx.add_record("recon", "travis", "travis", "result", summary=f"{len(hosts)} live host(s) ranked",
                       rationale="; ".join(f"{_host_tier(h)}:{h.get('host', '?')}" for h in hosts[:8]),
                       data={"hosts": hosts})

        # -- SELECT: the top-tier hosts become the scan targets -------------------------------------
        targets = [h for h in hosts if _host_tier(h) in tiers and _host_url(h)][:max_hosts]
        if not targets:                # dead/empty discovery, or a single-host target - scan the base itself
            targets = [{"url": ctx.base_url, "host": (urlparse(ctx.base_url).hostname or ""), "interest": "high"}]
            _line("no hosts in the selected tiers - falling back to the base target")
    _line("scan targets: " + ", ".join(_host_url(h) for h in targets))

    # -- SCAN: bob fast pass, then caleb deep pass where warranted -------------------------------------
    _phase("SCAN  (bob fast pass -> caleb deep pass)")
    for h in targets:
        url, tier = _host_url(h), _host_tier(h)
        hn = (urlparse(url).hostname or "").lower()      # record the host so the report's count is real
        if hn:
            hs = ctx.landscape.setdefault("surface", {}).setdefault("hosts", [])
            if hn not in hs:
                hs.append(hn)
        _line(f"bob -> {url}")
        _prov.reasoning_label("bob")
        be = _cli_capture(["ai", "bob", url] + common)
        bn = sum(1 for f in (be.get("data") or []) if isinstance(f, dict) and ctx.add_finding(f, by="bob"))
        if be.get("error"):
            _line(f"  bob: {be['error']}")
        _line(f"  bob: {bn} finding(s)")
        ctx.add_record("scan", "bob", "bob", "result", summary=f"{bn} finding(s) @ {url}",
                       data={"url": url, "count": bn})

        if do_deep and (h.get("explicit") or _worth_deep(tier, be)):
            _line(f"caleb -> {url}")
            _prov.reasoning_label("caleb")
            creds = (["--creds", opts["creds"]] if opts.get("creds") else [])
            creds += (["--creds-b", opts["creds_b"]] if opts.get("creds_b") else [])
            ce = _cli_capture(["ai", "caleb", url] + creds + common)
            cn = sum(1 for f in (ce.get("data") or []) if isinstance(f, dict) and ctx.add_finding(f, by="caleb"))
            if ce.get("error"):
                _line(f"  caleb: {ce['error']}")
            _line(f"  caleb: {cn} finding(s)")
            ctx.add_record("scan", "caleb", "caleb", "result", summary=f"{cn} finding(s) @ {url}",
                           data={"url": url, "count": cn})
        else:
            _line("  caleb: skipped (nothing worth a deep pass)")

    # -- VERIFY: independent existence re-check (proven gate, kept) ------------------------------------
    _phase("VERIFY")
    vres = Verifier().verify(ctx, runner)
    for d in vres["dropped"]:
        _line(f"DROP {d['id']} ({d['title']}) - {d['reason']}")
    _line(f"{vres['kept']} finding(s) exist and stand")

    # -- CONSOLIDATE: collapse provably-identical findings (proven, kept) ------------------------------
    _phase("CONSOLIDATE")
    _prov.reasoning_label("consolidator")
    cons = Consolidator().consolidate(ctx, provider)
    for m in cons.get("merges", []):
        _line(f"{' + '.join(m['ids'])} -> {m['kept']} ({m['title']})")
    if not cons.get("merges"):
        _line("no merge - nothing provably identical")

    # -- REPORT: CEO executive summary + technical findings -------------------------------------------
    _phase("REPORT")
    _prov.reasoning_label("reporter")
    report = Reporter().report(ctx, provider)
    ctx.add_record("report", "reporter", "reporter", "report", summary="final report", data={"text": report})
    return report

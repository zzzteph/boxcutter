"""irvin - the CONDUCTOR, exposed as a boxcutter subcommand.

`boxcutter irvin <target>` runs the lean, fixed pipeline over the proven agents: travis discovers and ranks
the live hosts, bob does a fast surface pass on each top host, caleb does the deep authenticated pass where
it's worth it, then the findings are verified, consolidated, and written up as a CEO executive summary plus a
technical findings table. No suggester council, no runtime-spawned agents - the same agents in the same order
every run.

Every agent's reasoning (native thinking + the one-line narration) streams live to stderr and is captured
per-agent; --reasoning-dir writes one trace file per agent. irvin is standalone: its own runner + LLM
provider.

  docker run --rm -e ANTHROPIC_API_KEY ghcr.io/zzzteph/boxcutter irvin example.com
  OPENAI_API_KEY=...  python3 boxcutter.py irvin https://target --provider openai --quick
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

from ..core.args import add_common_args
from ..core.envelope import output_result
from ..irvin import pipeline
from . import provider as _prov
from ..irvin.context import Context
from .provider import PROVIDERS, add_ai_provider_args, make_provider
from ..irvin.runner import Runner

NAME = "irvin"
KIND = "findings"
HELP = "Conductor: travis -> bob -> caleb, verified + consolidated, with a CEO report and per-agent reasoning."


def add_arguments(parser) -> None:
    parser.add_argument("target", nargs="?",
                        help="Domain to discover and hunt. Omit it when you pass --hosts / --hosts-file.")
    add_ai_provider_args(parser)          # --provider/--model/--api-key/--llm-proxy-url (shared by every ai agent)
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Auth header sent on every request by every sub-agent (e.g. 'Cookie: session=...'). "
                             "Repeatable.")
    parser.add_argument("--context", dest="context", default="", metavar="TEXT",
                        help="Free-text briefing forwarded to every sub-agent: what the target is, what's out "
                             "of scope, what to focus on. A credential/token mentioned here is kept private.")
    parser.add_argument("--creds", dest="creds", default=None, metavar="USER:PASS",
                        help="Identity A credentials for caleb's authenticated deep pass (agent-driven login).")
    parser.add_argument("--creds-b", dest="creds_b", default=None, metavar="USER:PASS",
                        help="Identity B credentials, for caleb's two-account BOLA/BFLA tests.")
    parser.add_argument("--scope", dest="scope", action="append", default=[], metavar="HOST",
                        help="Extra in-scope host for the verify re-check (repeatable) - exact host or "
                             "*.wildcard. Defaults to the target host only.")
    parser.add_argument("--hosts", dest="hosts", default=None, metavar="H,H",
                        help="Scan this explicit comma-separated list of hosts/URLs and SKIP travis discovery. "
                             "Use instead of, or alongside, a target domain.")
    parser.add_argument("--hosts-file", dest="hosts_file", default=None, metavar="PATH",
                        help="Like --hosts but read one host/URL per line from PATH (# comments and blanks "
                             "ignored). Also skips discovery.")
    # -- conductor knobs -----------------------------------------------------------------------------------
    parser.add_argument("--max-hosts", dest="max_hosts", type=int, default=6, metavar="N",
                        help="Scan at most N top-ranked hosts from recon (default 6).")
    parser.add_argument("--tiers", dest="tiers", default="critical,high", metavar="T,T",
                        help="Which travis interest tiers to scan (default 'critical,high').")
    parser.add_argument("--triage-top", dest="triage_top", type=int, default=15, metavar="N",
                        help="How many hosts travis LLM-triages during recon (default 15; 0 = deterministic).")
    parser.add_argument("--quick", dest="quick", action="store_true",
                        help="Bob's fast surface pass only - skip caleb's deep pass entirely.")
    # -- reasoning capture ---------------------------------------------------------------------------------
    parser.add_argument("--reasoning", dest="reasoning", type=int, default=3000, metavar="TOKENS",
                        help="Native-thinking token budget per model turn (default 3000; 0 disables it). Every "
                             "agent's thinking is captured and streamed live.")
    parser.add_argument("--no-stream-reasoning", dest="no_stream_reasoning", action="store_true",
                        help="Do not echo captured reasoning to stderr as the run happens (still captured).")
    parser.add_argument("--reasoning-dir", dest="reasoning_dir", default=None, metavar="DIR",
                        help="Write one reasoning-trace file per agent into DIR (native thinking + narration).")
    # -- outputs -------------------------------------------------------------------------------------------
    parser.add_argument("--report", dest="report", default=None, metavar="PATH",
                        help="Also save the final Markdown report to PATH (it is printed at the end too).")
    parser.add_argument("--trail", dest="trail", nargs="?", const="-", default=None, metavar="PATH",
                        help="Emit the machine-parsable run trail (JSON): bare --trail prints it, --trail PATH "
                             "writes it.")
    parser.add_argument("--out-dir", dest="out_dir", default=None, metavar="DIR",
                        help="Save everything into DIR: report.md, trail.json, and a reasoning/ folder.")
    # standard tool output flags (--output/--jsonl/--table/--debug): default stdout is the JSON findings
    # envelope, parseable exactly like every other tool; --table prints the human Markdown report instead.
    add_common_args(parser)


def _dump_reasoning(sink, out_dir: str) -> list:
    """Write one Markdown trace per agent from the captured reasoning sink. Returns the agent names written."""
    os.makedirs(out_dir, exist_ok=True)
    by_agent: dict = {}
    for rec in sink:
        by_agent.setdefault(rec.get("agent") or "unknown", []).append(rec)
    for agent, recs in by_agent.items():
        with open(os.path.join(out_dir, f"{agent}.reasoning.md"), "w", encoding="utf-8") as fh:
            fh.write(f"# Reasoning trace: {agent}\n\n{len(recs)} model turn(s).\n\n")
            for i, r in enumerate(recs, 1):
                calls = f"  (tool calls: {', '.join(r['calls'])})" if r.get("calls") else ""
                fh.write(f"## turn {i}{calls}\n\n")
                if r.get("reasoning"):
                    fh.write("**thinking:**\n\n" + r["reasoning"].strip() + "\n\n")
                if r.get("narration"):
                    fh.write("**said:** " + r["narration"].strip() + "\n\n")
    return sorted(by_agent)


def _collect_hosts(args) -> list:
    """The explicit host/URL list from --hosts and/or --hosts-file, normalized to URLs and de-duped. Empty when
    neither is given (Irvin then discovers hosts with travis). Lines starting with # and blanks are ignored."""
    raw = []
    if getattr(args, "hosts", None):
        raw += args.hosts.split(",")
    if getattr(args, "hosts_file", None):
        with open(args.hosts_file, encoding="utf-8") as fh:
            raw += fh.read().splitlines()
    out = []
    for h in (x.strip() for x in raw):
        if not h or h.startswith("#"):
            continue
        u = h if h.startswith(("http://", "https://")) else "https://" + h
        if u not in out:
            out.append(u)
    return out


def _reasoning_appendix(sink: list, reasoning_dir) -> str:
    """A short, deterministic 'how it reasoned' section for the end of the report: per-agent model-turn counts,
    and where to find the full thinking. Empty when nothing was captured (reasoning off)."""
    if not sink:
        return ""
    per: dict = {}
    for r in sink:
        per[r.get("agent") or "?"] = per.get(r.get("agent") or "?", 0) + 1
    lines = "\n".join(f"- {ag}: {n} model turn(s)" for ag, n in sorted(per.items()))
    where = (f"Full native thinking + narration per agent: `{reasoning_dir}/`." if reasoning_dir
             else "Re-run with `--reasoning-dir DIR` to dump the full per-agent thinking + narration.")
    return (f"\n\n## Reasoning trace\n\n{len(sink)} model turn(s) captured across the run:\n\n"
            f"{lines}\n\n{where}\n")


def run(args) -> int:
    try:
        explicit = _collect_hosts(args)          # explicit --hosts/--hosts-file -> skip travis discovery
    except OSError as exc:
        sys.stderr.write(f"boxcutter irvin: cannot read --hosts-file: {exc}\n")
        return 2
    if not args.target and not explicit:
        sys.stderr.write("boxcutter irvin: pass a target domain, or --hosts / --hosts-file\n")
        return 2

    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key and getattr(provider_cls, "requires_key", True):
        sys.stderr.write(f"boxcutter irvin: provide --api-key or set {provider_cls.env} "
                         f"for --provider {args.provider}\n")
        return 2

    seed = args.target or explicit[0]
    base_url = seed if seed.startswith(("http://", "https://")) else "https://" + seed
    base_host = (urlparse(base_url).hostname or "").lower()
    target_label = args.target or ", ".join(sorted({(urlparse(u).hostname or u) for u in explicit}))[:80]
    ctx = Context(target=target_label, base_url=base_url, brief=(args.context or "").strip())

    # Reasoning capture: one shared sink every agent (and the conductor's own reporter/consolidator) writes to
    # via make_provider. Streams live unless silenced. reasoning=0 turns native thinking off entirely.
    reasoning = max(0, int(args.reasoning or 0))
    sink: list = []
    stream = reasoning > 0 and not args.no_stream_reasoning
    _prov.set_reasoning_context(sink=sink, label="", stream=stream, reasoning=reasoning)

    provider = make_provider(args.provider, args.model, key, base_url=args.base_url, reasoning=reasoning)
    headers = list(args.header or [])
    explicit_hosts = [h for h in ((urlparse(u).hostname or "") for u in explicit) if h]
    runner = Runner(aggressive=True, base_host=base_host,
                    extra_hosts=list(args.scope or []) + explicit_hosts, global_headers=headers)

    opts = {"provider": args.provider, "model": args.model, "api_key": args.api_key, "base_url": args.base_url,
            "headers": headers, "context": (args.context or "").strip(), "creds": args.creds,
            "creds_b": args.creds_b, "hosts": explicit, "max_hosts": args.max_hosts,
            "tiers": [t.strip() for t in (args.tiers or "").split(",") if t.strip()],
            "triage_top": args.triage_top, "deep": not args.quick, "sink": sink}

    mode = f"{len(explicit)} host(s), discovery skipped" if explicit else "travis -> bob -> caleb"
    sys.stderr.write(f"irvin :: target={target_label} provider={args.provider} "
                     f"[conductor: {mode}]  reasoning={'on' if reasoning else 'off'}\n")

    report = ""
    try:
        report = pipeline.run(provider, ctx, runner, opts)
    finally:
        _prov.clear_reasoning_context()
        from ..core.cdp import close_all_sessions
        close_all_sessions()          # tear down any browser session a sub-agent left open

    final = (report or "(no report generated)") + _reasoning_appendix(sink, args.reasoning_dir)
    # Output exactly like every other tool: --table renders the FINDINGS as a table; otherwise the JSON
    # findings envelope (each finding severity/title/url/evidence, parseable uniformly). The Markdown report
    # rides along in extra["report"], and --report / --out-dir write it to disk.
    output_result(ctx.landscape["findings"], args.output,
                  extra={"target": ctx.base_url, "report": report, "reasoning_records": len(sink)})

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(final + "\n")
        sys.stderr.write(f"irvin :: report written to {args.report}\n")

    if args.reasoning_dir:
        written = _dump_reasoning(sink, args.reasoning_dir)
        sys.stderr.write(f"irvin :: reasoning traces written to {args.reasoning_dir}/ ({', '.join(written)})\n")

    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, "report.md"), "w", encoding="utf-8") as fh:
            fh.write(final + "\n")
        with open(os.path.join(args.out_dir, "trail.json"), "w", encoding="utf-8") as fh:
            fh.write(ctx.to_json())
        _dump_reasoning(sink, os.path.join(args.out_dir, "reasoning"))
        sys.stderr.write(f"irvin :: artifacts saved to {args.out_dir}/ (report.md, trail.json, reasoning/)\n")

    if args.trail == "-":
        print("\n===== IRVIN RUN TRAIL (JSON) =====")
        print(ctx.to_json())
    elif args.trail:
        with open(args.trail, "w", encoding="utf-8") as fh:
            fh.write(ctx.to_json())
        sys.stderr.write(f"irvin :: run trail written to {args.trail}\n")

    return 0

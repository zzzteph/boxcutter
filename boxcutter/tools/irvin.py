"""irvin - a pipeline bug-hunter (council of suggesters + concluder/planner/executors/reporter), exposed as
a boxcutter subcommand.

`boxcutter irvin <target>` runs the IRVIN pipeline: each round the suggester COUNCIL advises (plus a
mandated MINORITY-REPORT dissent), the CONCLUDER (council head) prioritizes with a verdict for every
suggestion, the PLANNER tailors executor steps, the EXECUTORS do+verify the work, and on convergence the
REPORTER writes up. The full decision trail is machine-parsable. irvin is standalone: its own runner + LLM
provider, its own agent registry.

  docker run --rm -e ANTHROPIC_API_KEY ghcr.io/zzzteph/boxcutter irvin https://target
  OPENAI_API_KEY=...  python3 boxcutter.py irvin https://target --provider openai
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

from ..irvin import briefing, pipeline
from ..irvin.context import Context
from ..irvin.provider import PROVIDERS, add_ai_provider_args
from ..irvin.runner import Runner

NAME = "irvin"
KIND = "items"
HELP = "Pipeline bug-hunter: suggester council -> concluder -> planner -> executors -> reporter (LLM-driven)."


def add_arguments(parser) -> None:
    parser.add_argument("target", nargs="?", help="URL, host, or domain to hunt")
    add_ai_provider_args(parser)          # --provider/--model/--api-key/--base-url (shared by every ai agent)
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Auth header for identity A - sent on EVERY request (e.g. 'Cookie: session=...'). "
                             "Repeatable.")
    parser.add_argument("--header-b", dest="header_b", action="append", default=[], metavar="NAME: VALUE",
                        help="Auth header for a 2nd identity B, for BOLA cross-actor tests (repeatable). NOT "
                             "sent globally - it's the comparison actor, attached only when B is under test.")
    parser.add_argument("--creds", dest="creds", default=None, metavar="USER:PASS",
                        help="Log in as identity A before round 1 - agent-driven, so it can handle a "
                             "multi-step/identifier-first login flow, not just a simple form. --login-url is an "
                             "optional hint: without it the agent DISCOVERS the login page itself. If the "
                             "session later appears to expire mid-run, the same agent re-logs-in itself using "
                             "this credential - it is never shown to any LLM, only a placeholder is")
    parser.add_argument("--login-url", dest="login_url", default=None, metavar="URL",
                        help="Optional hint: identity A's login page. Omit it and the agent finds the login "
                             "page itself from the target")
    parser.add_argument("--creds-b", dest="creds_b", default=None, metavar="USER:PASS",
                        help="Log in as a 2nd identity B before the run starts, for BOLA (--login-url-b optional)")
    parser.add_argument("--login-url-b", dest="login_url_b", default=None, metavar="URL",
                        help="Optional hint: identity B's login page (agent discovers it if omitted)")
    parser.add_argument("--context", dest="context", default="", metavar="TEXT",
                        help="Free-text briefing for every agent - what the target IS, what's out of scope, "
                             "what to focus on, e.g. \"a food-ordering platform; the /admin panel is out of "
                             "scope; focus on checkout and account APIs\". You can also state RULES here in "
                             "plain language and they're applied automatically: scope hosts/wildcards (e.g. "
                             "*.example.com) and request headers/tokens to send on every call (e.g. a "
                             "Tester-Token) - a token you mention is kept private, not broadcast to the model")
    parser.add_argument("--scope", dest="scope", action="append", default=[], metavar="HOST",
                        help="Extra in-scope host (repeatable) - an exact host OR a wildcard like "
                             "*.example.com (which covers every subdomain AND the apex). Scope defaults to "
                             "ONLY the target host (no automatic subdomains); add each host/wildcard you want "
                             "tested explicitly, e.g. a SPA's cross-origin API backend the browser tools "
                             "surfaced, or a subdomain recon reports as found-but-out-of-scope")
    parser.add_argument("--max-rounds", dest="max_rounds", type=int, default=8,
                        help="Cap on pipeline rounds (default 8); the loop also stops when the council converges")
    parser.add_argument("--agent", dest="agent", default=None, metavar="NAME",
                        help="Sanity-run ONE agent standalone against the target - no council/planner/loop. An "
                             "executor name (e.g. explore, recon, access-control, auth) runs it and prints its "
                             "verified handoff + action summary; a suggester name prints its advice. Great for "
                             "evaluating a single agent's output and actions in isolation")
    parser.add_argument("--agent-brief", dest="agent_brief", default="", metavar="TEXT",
                        help="Commission text for --agent (what you want it to do). Defaults to a generic "
                             "'do your job against the target' brief")
    parser.add_argument("--trail", dest="trail", nargs="?", const="-", default=None, metavar="PATH",
                        help="Emit the full machine-parsable decision trail (JSON). Bare --trail prints it to "
                             "the console; --trail PATH writes it to that file")
    parser.add_argument("--report", dest="report", default=None, metavar="PATH",
                        help="Also SAVE the final Markdown report to PATH (it is always printed at the end too)")
    parser.add_argument("--out-dir", dest="out_dir", default=None, metavar="DIR",
                        help="Save ALL run artifacts into DIR at the end: report.md, trail.json, trace.dot, "
                             "actions.dot (plus rendered .png if graphviz 'dot' is installed). Without it, the "
                             "report prints to stdout; add --trail/--graph/--actions to print those too.")
    parser.add_argument("--graph", dest="graph", nargs="?", const="-", default=None, metavar="PATH",
                        help="At the end, emit a Graphviz DOT of what actually happened (the run trace, from "
                             "the context). Bare --graph prints it; --graph PATH writes it. Render with dot")
    parser.add_argument("--actions", dest="actions", nargs="?", const="-", default=None, metavar="PATH",
                        help="At the end, emit a Graphviz DOT of the ACTIONS taken (steps + decisions per round: "
                             "plan->thin->execute->escalate->adjust) for a visual walkthrough. Bare --actions "
                             "prints it; --actions PATH writes it. Render with dot")


def _as_headers(values):
    out = []
    for h in values:
        out += ["--header", h]
    return out


def _report_text(ctx) -> str:
    """The final Markdown report the reporter produced (stored on the trail by the pipeline)."""
    return next((r.data.get("text", "") for r in reversed(ctx.trail) if r.kind == "report"), "")


def _write_artifacts(ctx, out_dir: str) -> list:
    """Dump every run artifact into out_dir: the Markdown report, the JSON decision trail, and both Graphviz
    graphs (run trace + actions). If graphviz `dot` is installed, also render the graphs to PNG. Returns the
    filenames written."""
    import shutil
    import subprocess
    from ..irvin.graphviz import actions_dot, trace_dot

    os.makedirs(out_dir, exist_ok=True)
    md = _report_text(ctx)
    artifacts = {"report.md": (md + "\n") if md else "(no report generated)\n",
                 "trail.json": ctx.to_json(),
                 "trace.dot": trace_dot(ctx),
                 "actions.dot": actions_dot(ctx)}
    written = []
    for name, content in artifacts.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
            fh.write(content)
        written.append(name)
    if shutil.which("dot"):          # render the DOT graphs to PNG when graphviz is available
        for dot_name in ("trace.dot", "actions.dot"):
            png = dot_name[:-4] + ".png"
            try:
                subprocess.run(["dot", "-Tpng", os.path.join(out_dir, dot_name), "-o",
                                os.path.join(out_dir, png)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                if os.path.exists(os.path.join(out_dir, png)):
                    written.append(png)
            except Exception:  # noqa: BLE001 - rendering is a nicety; never fail the run over it
                pass
    return written


def run(args) -> int:
    from ..irvin.agents import validate_registry
    validate_registry()

    if not args.target:
        sys.stderr.write("boxcutter irvin: a target is required\n")
        return 2
    # --login-url is only a HINT for where to log in; --creds is what actually logs in. A login URL with no
    # credentials to submit is meaningless, but credentials with no URL are fine - the agent discovers the page.
    if args.login_url and not args.creds:
        sys.stderr.write("boxcutter irvin: --login-url needs --creds (a login page with no identity to log in as)\n")
        return 2
    if args.login_url_b and not args.creds_b:
        sys.stderr.write("boxcutter irvin: --login-url-b needs --creds-b\n")
        return 2

    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"boxcutter irvin: provide --api-key or set {provider_cls.env} "
                         f"for --provider {args.provider}\n")
        return 2

    base_url = args.target if args.target.startswith(("http://", "https://")) else "https://" + args.target
    base_host = (urlparse(base_url).hostname or "").lower()
    ctx = Context(target=args.target, base_url=base_url, brief=args.context.strip())
    if args.header:
        ctx.add_identity("A", _as_headers(args.header), "cli")
    if args.header_b:
        ctx.add_identity("B", _as_headers(args.header_b), "cli")

    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)

    # RULES-IN-CONTEXT: let the operator express settings in the plain-language --context instead of flags -
    # an LLM pass pulls scope host-patterns and global request headers (a Tester-Token, an org auth header) out
    # of the briefing. Secrets it finds move into the private global-header channel and are stripped from the
    # broadcast focus, so a token in --context is a convenience, not a leak. Explicit flags still stack on top.
    brief_cfg = briefing.parse(provider, args.context, base_host)
    if brief_cfg.get("focus"):
        ctx.brief = brief_cfg["focus"]        # cleaned focus (secrets removed) becomes what's broadcast
    # An operator who passes `--header "Cookie: <session>"` means "act as this logged-in user" - i.e. send it
    # on EVERY request, not only when an access-control call happens to opt into identity A. So identity A's
    # headers ALSO seed the global, auto-injected channel (same contract as `boxcutter ai visor` and as a
    # Cookie named in --context). --header-b stays identity-only: B is the COMPARISON actor for BOLA, never
    # the default session. --context-extracted headers stack on top (a header name --header already set wins).
    cli_headers = list(args.header)
    ctx_names = {h.split(":", 1)[0].strip().lower() for h in cli_headers}
    global_headers = cli_headers + [h for h in brief_cfg.get("headers", [])
                                    if h.split(":", 1)[0].strip().lower() not in ctx_names]
    if global_headers:
        sys.stderr.write(f"irvin :: {len(global_headers)} header(s) sent on EVERY request "
                         "(from --header / --context; values hidden)\n")

    # a login URL the operator explicitly gave us is obviously meant to be reachable, even when it's on a
    # separate host (a common SSO/auth subdomain) - both for this bootstrap login and for the agent-driven
    # re-login later, which reuses this same Runner/scope. Scope entries may be exact hosts OR *.wildcards.
    ctx_login_hosts = [urlparse(c["login_url"]).hostname for c in brief_cfg.get("creds", []) if c.get("login_url")]
    login_hosts = [urlparse(u).hostname for u in (args.login_url, args.login_url_b) if u] + ctx_login_hosts
    extra_hosts = [*args.scope, *brief_cfg.get("scope", []), *(h for h in login_hosts if h)]
    if brief_cfg.get("scope"):
        sys.stderr.write(f"irvin :: scope from --context: {', '.join(brief_cfg['scope'])}\n")

    runner = Runner(aggressive=True, base_host=base_host, extra_hosts=extra_hosts, global_headers=global_headers)

    if args.creds:
        user, _, pw = args.creds.partition(":")
        ctx.store_creds("A", user, pw, args.login_url)
    if args.creds_b:
        user, _, pw = args.creds_b.partition(":")
        ctx.store_creds("B", user, pw, args.login_url_b)
    # credentials named in the plain-language --context are stored the SAME private way as --creds (the
    # placeholder mechanism; never broadcast) so "creds are user:pass" in the prose just works and triggers the
    # agent-driven bootstrap login. Explicit --creds for a label wins (don't overwrite it).
    for c in brief_cfg.get("creds", []):
        if not ctx.has_creds(c["label"]):
            ctx.store_creds(c["label"], c["user"], c["password"], c["login_url"] or None)
    if brief_cfg.get("creds"):
        sys.stderr.write(f"irvin :: {len(brief_cfg['creds'])} credential(s) parsed from --context "
                         "(stored privately, values hidden)\n")
    # the actual login (initial AND any later refresh) is agent-driven - see pipeline.py:_bootstrap_auth and
    # agents/suggesters.py:AuthProfile/agents/executors.py:Auth. A fixed selector-matching call can't reliably
    # handle a multi-step/identifier-first flow (e.g. Keycloak splitting username and password across screens,
    # or fields with no id/name at all) - that needs the same judgment a mid-run refresh needs.

    if args.agent:
        from ..irvin.agents import EXECUTORS, SUGGESTERS
        if args.agent not in set(EXECUTORS) | {s.name for s in SUGGESTERS}:
            sys.stderr.write(f"boxcutter irvin: no agent '{args.agent}'.\n"
                             f"  executors:  {', '.join(sorted(EXECUTORS))}\n"
                             f"  suggesters: {', '.join(sorted(s.name for s in SUGGESTERS))}\n")
            return 2
        sys.stderr.write(f"irvin :: target={args.target} provider={args.provider} "
                         f"[single-agent sanity run :: {args.agent}]\n")
    else:
        sys.stderr.write(f"irvin :: target={args.target} provider={args.provider} "
                         "[council -> concluder -> planner -> executors -> reporter]\n")

    try:
        if args.agent:
            pipeline.run_agent(args.agent, provider, ctx, runner, brief=args.agent_brief, target=base_url)
        else:
            pipeline.run(provider, ctx, runner, max_rounds=args.max_rounds)
    finally:
        from ..core.cdp import close_all_sessions
        close_all_sessions()          # tear down any persistent browser session the explorer left open

    if args.out_dir:                 # one folder with everything: report + trail + both graphs (+ rendered png)
        written = _write_artifacts(ctx, args.out_dir)
        sys.stderr.write(f"\nirvin :: run artifacts saved to {args.out_dir}/  ({', '.join(written)})\n")

    if args.report:
        # the reporter's Markdown (already printed by the pipeline) is stored on the trail - save a copy
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(_report_text(ctx) + "\n")
        sys.stderr.write(f"\nirvin :: Markdown report written to {args.report}\n")

    if args.trail == "-":
        print("\n===== IRVIN DECISION TRAIL (JSON) =====")
        print(ctx.to_json())
    elif args.trail:
        with open(args.trail, "w", encoding="utf-8") as fh:
            fh.write(ctx.to_json())
        sys.stderr.write(f"\nirvin :: decision trail written to {args.trail}\n")

    if args.graph is not None:
        from ..irvin.graphviz import trace_dot
        graph = trace_dot(ctx)
        if args.graph == "-":
            print("\n===== IRVIN RUN TRACE (Graphviz DOT) =====")
            print(graph)
        else:
            with open(args.graph, "w", encoding="utf-8") as fh:
                fh.write(graph)
            sys.stderr.write(f"\nirvin :: run trace (DOT) written to {args.graph}\n")

    if args.actions is not None:
        from ..irvin.graphviz import actions_dot
        graph = actions_dot(ctx)
        if args.actions == "-":
            print("\n===== IRVIN ACTIONS (Graphviz DOT) =====")
            print(graph)
        else:
            with open(args.actions, "w", encoding="utf-8") as fh:
                fh.write(graph)
            sys.stderr.write(f"\nirvin :: actions graph (DOT) written to {args.actions}\n")
    return 0

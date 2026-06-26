"""bob - autonomous multi-agent bug-hunter, exposed as a boxcutter subcommand.

`boxcutter bob <target>` runs an adaptive team of boxcutter-only LLM agents (planner, auth,
discovery, js-analyzer, recon-ranker, fingerprint, profile, api, graphql, exposure, fuzzer, access,
lateral, validator, correlator, reporter). They share one engagement context, harvest credentials,
move laterally, chase chains, and produce a professional report. The coordinator self-selects which
agents to run from what it discovers - there is no roster to configure.

bob is intentionally low-config: it ALWAYS hunts aggressively on the authorized target and ALWAYS
auto-selects agents. It reaches the LLM over HTTP (requests-only, no SDKs); set an API key in the
environment. Unlike other tools it streams progress to stderr and prints the final report to stdout.

  docker run --rm -e ANTHROPIC_API_KEY ghcr.io/zzzteph/boxcutter bob https://target
  OPENAI_API_KEY=...   python3 boxcutter.py bob https://target --provider openai
  LITELLM_API_KEY=... LITELLM_BASE_URL=http://localhost:4000  python3 boxcutter.py bob https://target --provider litellm --model claude-sonnet-4-6
  python3 boxcutter.py bob https://target --header "Authorization: Bearer A" --header-b "Authorization: Bearer B"
  python3 boxcutter.py bob https://target --show-prompts        # inspect each agent's full assembled prompt
"""

from __future__ import annotations

import os
import sys

from ..agent.providers import PROVIDERS
from ..agent.runner import InProcessRunner
from ..agent.context import Context, Session
from ..agent.agents import PIPELINE
from ..agent.orchestrator import run_pipeline
from ..agent import session as auth_session

NAME = "bob"
KIND = "items"
HELP = "Autonomous multi-agent bug-hunter (LLM-driven; needs ANTHROPIC_API_KEY / OPENAI_API_KEY / LITELLM_API_KEY)."

_TOOL_TIMEOUT = 600


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL, host, domain, or spec URL to hunt")
    parser.add_argument("--provider", choices=list(PROVIDERS), default="anthropic",
                        help="LLM provider (default: anthropic; 'litellm' fronts any provider via your gateway)")
    parser.add_argument("--model", default=None, help="Model id (defaults per provider)")
    parser.add_argument("--api-key", dest="api_key", default=None,
                        help="LLM API key (default: the provider's env var, e.g. ANTHROPIC_API_KEY)")
    parser.add_argument("--base-url", dest="base_url", default=None,
                        help="LLM API base URL (default: provider default or its *_BASE_URL env; e.g. a LiteLLM gateway)")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Auth header for identity A (repeatable)")
    parser.add_argument("--header-b", dest="header_b", action="append", default=[], metavar="NAME: VALUE",
                        help="Auth header for a 2nd identity B, for BOLA/BFLA (repeatable)")
    parser.add_argument("--creds", default=None, metavar="USER:PASS",
                        help="Credentials for identity A; bob logs in and self-manages access/refresh tokens")
    parser.add_argument("--creds-b", dest="creds_b", default=None, metavar="USER:PASS",
                        help="Credentials for a 2nd identity B (for BOLA/BFLA)")
    parser.add_argument("--login-url", dest="login_url", default=None,
                        help="Login endpoint for --creds (omit and bob's auth agent tries to discover it)")
    parser.add_argument("--steps", action="store_true",
                        help="Verbose: print a one-line result summary after every tool call")
    parser.add_argument("--show-prompts", dest="show_prompts", action="store_true",
                        help="Print each agent's full assembled system prompt and exit (no API key needed)")


def _detect_entry(target: str) -> str:
    """Figure out what the user pointed bob at: a bare domain, a URL, a single endpoint, or an API spec."""
    if not target.startswith(("http://", "https://")):
        return "domain"
    low = target.lower()
    base = low.split("?", 1)[0].rstrip("/")
    if any(m in low for m in ("swagger", "openapi", "api-docs")) or base.endswith((".yaml", ".yml")):
        return "spec"
    from urllib.parse import urlparse
    path = (urlparse(target).path or "").strip("/")
    last = path.split("/")[-1] if path else ""
    if "?" in target or (path and (len(path.split("/")) >= 2 or "." in last)):
        return "endpoint"
    return "url"


def _build_ctx(args) -> Context:
    ctx = Context(target=args.target, mode="complete")
    ctx.aggressive = True   # bob always hunts aggressively on the authorized target
    ctx.base_url = args.target if args.target.startswith(("http://", "https://")) else "https://" + args.target
    ctx.entry = _detect_entry(args.target)
    # seed the surface so the testers act on exactly what the user pointed at
    if ctx.entry == "spec":
        ctx.surface["spec"].append(ctx.base_url)
        ctx.surface["api"].append(ctx.base_url)
        ctx.surface["tier1"].append(ctx.base_url)
    elif ctx.entry in ("url", "endpoint"):
        ctx.surface["endpoints"].append(ctx.base_url)
        ctx.surface["tier1"].append(ctx.base_url)
        if "?" in ctx.base_url:
            ctx.surface["param_urls"].append(ctx.base_url)
    if args.header:
        ctx.identities["A"] = _as_headers(args.header)
    if args.header_b:
        ctx.identities["B"] = _as_headers(args.header_b)
    for label, raw in (("A", args.creds), ("B", args.creds_b)):
        if raw and ":" in raw:
            user, pw = raw.split(":", 1)
            ctx.sessions[label] = Session(label=label, creds=(user, pw), login_url=args.login_url or "")
    return ctx


def _login_sessions(ctx, runner):
    """Deterministically log in each --creds identity before the hunt, and seed its token."""
    for label, sess in ctx.sessions.items():
        if auth_session.login(sess, runner):
            ctx.sync_identity(sess)
            sys.stderr.write(f"bob :: identity {label} logged in ({sess.kind}); access+refresh self-managed\n")
        else:
            ctx.note(f"identity {label}: pre-login failed (need --login-url) - auth agent will try to discover it")


def run(args) -> int:
    if args.show_prompts:
        ctx = _build_ctx(args)
        tot_sys = tot_mem = 0
        for cls in PIPELINE:
            agent = cls(None, None, args)
            sp = agent.system_prompt(ctx)
            mem = agent.context_block(ctx)          # the shared memory (Context) sent with every turn
            tot_sys += len(sp); tot_mem += len(mem)
            print(f"\n{'=' * 80}\n# {agent.name}  -  system {len(sp)} chars (~{len(sp) // 4} tok) "
                  f"+ shared-memory {len(mem)} chars (~{len(mem) // 4} tok) "
                  f"= {len(sp) + len(mem)} chars (~{(len(sp) + len(mem)) // 4} tok)\n"
                  f"  (system = BASE doctrine + role objective + tool reference + judgment rubric; "
                  f"shared-memory = the live Context, grows as agents add findings/identities/surface)\n"
                  f"{'=' * 80}\n{sp}")
        print(f"\n{'=' * 80}\n# TOTALS  -  {len(PIPELINE)} agents: "
              f"system {tot_sys} chars (~{tot_sys // 4} tok), "
              f"shared-memory[seed] {tot_mem} chars (~{tot_mem // 4} tok)\n"
              f"  shared-memory shown is the INITIAL SEED; it grows during a run as findings, identities, "
              f"surface and handoffs accumulate (run with --steps to see live per-agent payload sizes).\n{'=' * 80}")
        return 0

    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"boxcutter bob: provide --api-key or set {provider_cls.env} for --provider {args.provider}\n")
        return 2

    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)
    runner = InProcessRunner(tool_timeout=_TOOL_TIMEOUT, aggressive=True)
    ctx = _build_ctx(args)
    sys.stderr.write(f"bob :: target={args.target} provider={args.provider} agents=auto [aggressive]\n\n")
    _login_sessions(ctx, runner)                      # self-managed auth: log in before the hunt
    run_pipeline(provider, runner, ctx, None, args)   # None => coordinator self-selects (auto)
    print("\n" + ctx.coverage_report())               # machine-generated facts the model can't fake
    return 0


def _as_headers(values):
    out = []
    for h in values:
        out += ["--header", h]
    return out

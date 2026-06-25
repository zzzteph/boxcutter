"""bob - autonomous multi-agent bug-hunter, exposed as a boxcutter subcommand.

`boxcutter bob <target>` runs a pipeline of adaptive, boxcutter-only LLM agents (planner, auth,
discovery, fingerprint, profile, api, exposure, fuzzer, access, lateral, reporter) that share one
engagement context, harvest credentials, move laterally, and chase chains to demonstrable impact.

Unlike the other tools this does not emit a JSON envelope - it streams agent progress to stderr and
prints the final findings report to stdout. It needs an LLM API key in the environment
(ANTHROPIC_API_KEY or OPENAI_API_KEY) and reaches the LLM over HTTP (requests-only, no SDKs).

  docker run --rm -e ANTHROPIC_API_KEY ghcr.io/zzzteph/boxcutter bob https://target
  python3 boxcutter.py bob https://target --header "Authorization: Bearer A" --header-b "Authorization: Bearer B"
"""

from __future__ import annotations

import os
import sys

from ..agent.providers import PROVIDERS
from ..agent.runner import InProcessRunner
from ..agent.context import Context
from ..agent.agents import AGENTS, PIPELINE
from ..agent.orchestrator import run_pipeline

NAME = "bob"
KIND = "items"
HELP = "Autonomous multi-agent bug-hunter (LLM-driven; needs ANTHROPIC_API_KEY / OPENAI_API_KEY)."

_DEFAULT_ORDER = [cls.name for cls in PIPELINE]


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL, host, domain, or spec URL to hunt")
    parser.add_argument("--provider", choices=list(PROVIDERS), default="anthropic",
                        help="LLM provider (default: anthropic)")
    parser.add_argument("--model", default=None, help="Model id (defaults per provider)")
    parser.add_argument("--mode", choices=["fast", "complete"], default="fast")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Auth header for identity A (repeatable)")
    parser.add_argument("--header-b", dest="header_b", action="append", default=[], metavar="NAME: VALUE",
                        help="Auth header for a 2nd identity B, for BOLA/BFLA (repeatable)")
    parser.add_argument("--agents", default=",".join(_DEFAULT_ORDER),
                        help=f"Comma list / order of agents (default: {','.join(_DEFAULT_ORDER)})")
    parser.add_argument("--aggressive", action="store_true",
                        help="Allow state-mutating methods (PUT/PATCH/DELETE) on this authorized target")
    parser.add_argument("--tool-timeout", dest="tool_timeout", type=int, default=600,
                        help="Per-tool-call timeout in seconds")


def run(args) -> int:
    provider_cls = PROVIDERS[args.provider]
    key = os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"boxcutter bob: set {provider_cls.env} to use --provider {args.provider}\n")
        return 2

    names = [a.strip() for a in args.agents.split(",") if a.strip()]
    unknown = [a for a in names if a not in AGENTS]
    if unknown:
        sys.stderr.write(f"boxcutter bob: unknown agents {unknown} (known: {', '.join(_DEFAULT_ORDER)})\n")
        return 2

    provider = provider_cls(args.model or provider_cls.default_model, key)
    runner = InProcessRunner(tool_timeout=args.tool_timeout, aggressive=args.aggressive)

    ctx = Context(target=args.target, mode=args.mode)
    ctx.aggressive = args.aggressive
    ctx.base_url = args.target if args.target.startswith(("http://", "https://")) else "https://" + args.target
    if args.header:
        ctx.identities["A"] = _as_headers(args.header)
    if args.header_b:
        ctx.identities["B"] = _as_headers(args.header_b)

    sys.stderr.write(f"bob :: target={args.target} provider={args.provider} "
                     f"agents={','.join(names)}{' [aggressive]' if args.aggressive else ''}\n\n")
    run_pipeline(provider, runner, ctx, names, args)
    return 0


def _as_headers(values):
    out = []
    for h in values:
        out += ["--header", h]
    return out

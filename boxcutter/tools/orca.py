"""orca - queue-driven planner/advisor/executor bug-hunter, exposed as a boxcutter subcommand.

`boxcutter orca <target>` runs ORCA: an LLM PLANNER that owns a dynamic work-queue, a set of ADVISORS that
observe state and suggest next actions, and EXECUTORS that do the work (recon, fuzz, request battery,
sqlmap, exposure, report). The flow is built and extended at runtime and printed as one ordered, reasoned
plan. orca is standalone - it shares no code with bob - so you can run both and compare.

  docker run --rm -e ANTHROPIC_API_KEY ghcr.io/zzzteph/boxcutter orca https://target
  OPENAI_API_KEY=...  python3 boxcutter.py orca https://target --provider openai
  LITELLM_API_KEY=... python3 boxcutter.py orca https://target --provider litellm --model openai/gpt-5.1 --base-url URL
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

from ..orca.provider import PROVIDERS
from ..orca.runner import Runner
from ..orca.state import State
from ..orca import engine

NAME = "orca"
KIND = "items"
HELP = "Queue-driven planner/advisor/executor bug-hunter (LLM-driven; standalone from bob)."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL, host, or domain to hunt")
    parser.add_argument("--provider", choices=list(PROVIDERS), default="anthropic",
                        help="LLM provider (default: anthropic; 'litellm' fronts any provider via your gateway)")
    parser.add_argument("--model", default=None, help="Model id (defaults per provider)")
    parser.add_argument("--api-key", dest="api_key", default=None,
                        help="LLM API key (default: the provider's env var, e.g. ANTHROPIC_API_KEY)")
    parser.add_argument("--base-url", dest="base_url", default=None, help="LLM API base URL (e.g. a LiteLLM gateway)")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Auth header for identity A (repeatable)")
    parser.add_argument("--header-b", dest="header_b", action="append", default=[], metavar="NAME: VALUE",
                        help="Auth header for a 2nd identity B, for BOLA (repeatable)")
    parser.add_argument("--max-cycles", dest="max_cycles", type=int, default=None,
                        help="Cap on planner cycles (each is one LLM decision); default 60")
    parser.add_argument("--show-plan", dest="show_plan", action="store_true",
                        help="Print ORCA's planner system prompt + executor roster and exit (no API key needed)")


def _as_headers(values):
    out = []
    for h in values:
        out += ["--header", h]
    return out


def run(args) -> int:
    if args.show_plan:
        from ..orca.planner import SYSTEM
        print(SYSTEM)
        return 0

    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"boxcutter orca: provide --api-key or set {provider_cls.env} for --provider {args.provider}\n")
        return 2

    base_url = args.target if args.target.startswith(("http://", "https://")) else "https://" + args.target
    state = State(target=args.target, base_url=base_url)
    if args.header:
        state.identities["A"] = _as_headers(args.header)
    if args.header_b:
        state.identities["B"] = _as_headers(args.header_b)

    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)
    args._runner = Runner(aggressive=True, base_host=(urlparse(base_url).hostname or "").lower())
    sys.stderr.write(f"orca :: target={args.target} provider={args.provider} [planner/advisors/executors]\n\n")
    engine.run(provider, state, args)
    return 0

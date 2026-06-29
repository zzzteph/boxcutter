"""irvin - a pipeline bug-hunter (council of suggesters + concluder/planner/executors/reporter), exposed as
a boxcutter subcommand.

`boxcutter irvin <target>` runs the IRVIN pipeline: each round the suggester COUNCIL advises (plus a
mandated MINORITY-REPORT dissent), the CONCLUDER (council head) prioritizes with a verdict for every
suggestion, the PLANNER tailors executor steps, the EXECUTORS do+verify the work, and on convergence the
REPORTER writes up. The full decision trail is machine-parsable. irvin is standalone - it reuses only the
boxcutter tool layer (orca's runner + LLM provider) and shares no hunting logic with bob or orca.

  docker run --rm -e ANTHROPIC_API_KEY ghcr.io/zzzteph/boxcutter irvin https://target
  OPENAI_API_KEY=...  python3 boxcutter.py irvin https://target --provider openai
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

from ..irvin import pipeline
from ..irvin.context import Context
from ..orca.provider import PROVIDERS
from ..orca.runner import Runner

NAME = "irvin"
KIND = "items"
HELP = "Pipeline bug-hunter: suggester council -> concluder -> planner -> executors -> reporter (LLM-driven)."


def add_arguments(parser) -> None:
    parser.add_argument("target", nargs="?", help="URL, host, or domain to hunt")
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
    parser.add_argument("--max-rounds", dest="max_rounds", type=int, default=8,
                        help="Cap on pipeline rounds (default 8); the loop also stops when the council converges")
    parser.add_argument("--trail", dest="trail", nargs="?", const="-", default=None, metavar="PATH",
                        help="Emit the full machine-parsable decision trail (JSON). Bare --trail prints it to "
                             "the console; --trail PATH writes it to that file")
    parser.add_argument("--graph", dest="graph", nargs="?", const="-", default=None, metavar="PATH",
                        help="At the end, emit a Graphviz DOT of what actually happened (the run trace, from "
                             "the context). Bare --graph prints it; --graph PATH writes it. Render with dot")
    parser.add_argument("--show-roster", dest="show_roster", action="store_true",
                        help="Print the suggester/executor roster and exit (no API key needed)")
    parser.add_argument("--graphviz", dest="graphviz", action="store_true",
                        help="Print the pipeline diagram as Graphviz DOT and exit (render it yourself with dot)")
    parser.add_argument("--check", dest="check", action="store_true",
                        help="Validate that every executor's tools/flags are real, then exit (no API key needed)")


def _as_headers(values):
    out = []
    for h in values:
        out += ["--header", h]
    return out


def run(args) -> int:
    if args.show_roster:
        from ..irvin.agents import roster
        print(roster())
        return 0

    if args.graphviz:
        from ..irvin.graphviz import dot
        print(dot())
        return 0

    if args.check:
        from ..irvin.selfcheck import report
        return report()

    if not args.target:
        sys.stderr.write("boxcutter irvin: a target is required (or use --show-roster)\n")
        return 2

    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"boxcutter irvin: provide --api-key or set {provider_cls.env} "
                         f"for --provider {args.provider}\n")
        return 2

    base_url = args.target if args.target.startswith(("http://", "https://")) else "https://" + args.target
    ctx = Context(target=args.target, base_url=base_url)
    if args.header:
        ctx.add_identity("A", _as_headers(args.header), "cli")
    if args.header_b:
        ctx.add_identity("B", _as_headers(args.header_b), "cli")

    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)
    runner = Runner(aggressive=True, base_host=(urlparse(base_url).hostname or "").lower())
    sys.stderr.write(f"irvin :: target={args.target} provider={args.provider} "
                     "[council -> concluder -> planner -> executors -> reporter]\n")

    pipeline.run(provider, ctx, runner, max_rounds=args.max_rounds)

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
    return 0

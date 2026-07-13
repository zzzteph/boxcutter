"""visor - a STANDALONE visual login agent (no IRVIN pipeline).

Its one job: log in to a target with the supplied credentials by driving ONLY the `visual-driver` tool - it
looks at a coordinate-grid screenshot and clicks/types at coordinates with human-like mouse motion. A single
self-contained agent loop you can run on its own to test the visual driver end to end. By default it also
records a screenshot of every action into a trace directory so you can flip through exactly what happened.

  boxcutter visor https://app.example.com --creds "user@example.com:pass" \
    --provider litellm --model "openai/gpt-5.1" --api-key ... --base-url https://gateway.example.com

The password is never shown to the model - it types __USER_A__/__PASS_A__ tokens that are substituted with the
real values only when the click/type actually dispatches.
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlparse

from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_print, output_result
from ..irvin.agents.executors import Visor
from ..irvin.context import Context
from ..irvin.provider import PROVIDERS, add_ai_provider_args
from ..irvin.runner import Runner

NAME = "visor"
KIND = "items"
HELP = "Standalone visual login agent: drives only visual-driver to log in with supplied creds (no IRVIN pipeline)."


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL (the app root or its login page)")
    parser.add_argument("--creds", default=None, metavar="USER:PASS", help="Credentials to log in with (identity A)")
    parser.add_argument("--login-url", dest="login_url", default=None, metavar="URL",
                        help="Optional: the login page to start on (else the agent finds it from the target)")
    add_ai_provider_args(parser)          # --provider/--model/--api-key/--base-url (shared by every ai agent)
    parser.add_argument("--grid", type=int, default=50, metavar="PX", help="Coordinate-grid spacing (0 = off)")
    parser.add_argument("--trace", default="trace", metavar="DIR",
                        help="Save a screenshot of every action into DIR so you can flip through the run "
                             "(default ./trace, a trace/ folder under the current directory; in Docker pass "
                             "--trace /trace and mount -v \"$PWD/trace:/trace\"). Set '' to disable")
    parser.add_argument("--max-steps", dest="max_steps", type=int, default=20, help="Max agent steps")
    add_header_arg(parser)          # sent on every request (e.g. a Tester-Token to disable a bot check)
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    if not target:
        output_result([], args.output, "a target is required")
        return 2
    if not args.creds or ":" not in args.creds:
        output_result([], args.output, "visor needs --creds \"user:pass\" to log in")
        return 2

    provider_cls = PROVIDERS[args.provider]
    key = args.api_key or os.environ.get(provider_cls.env)
    if not key:
        sys.stderr.write(f"visor: provide --api-key or set {provider_cls.env} for --provider {args.provider}\n")
        return 2

    base_url = target if target.startswith(("http://", "https://")) else "https://" + target
    base_host = (urlparse(base_url).hostname or "").lower()
    ctx = Context(target=target, base_url=base_url, brief="")
    user, _, pw = args.creds.partition(":")
    ctx.store_creds("A", user, pw, args.login_url)

    provider = provider_cls(args.model or provider_cls.default_model, key, base_url=args.base_url)
    # keep the login page in scope even when it's on a separate SSO host; --header rides every request
    login_hosts = [urlparse(args.login_url).hostname] if args.login_url else []
    runner = Runner(aggressive=True, base_host=base_host,
                    extra_hosts=[h for h in login_hosts if h], global_headers=list(args.header or []))

    ex = Visor()
    ex.max_steps = args.max_steps
    ex._grid = args.grid
    ex._trace = os.path.abspath(args.trace) if args.trace else None
    start = args.login_url or base_url
    step = {"executor": "visor", "target": start, "ref": None, "avoid": "", "context": "",
            "brief": f"Log in to {start} with the supplied credentials, purely visually."}

    sys.stderr.write(f"visor :: target={target} provider={args.provider} model={args.model or provider_cls.default_model} "
                     f"[standalone visual login | grid={args.grid} | trace={ex._trace or 'off'}]\n")
    try:
        handoff = ex.run(ctx, step, runner, provider)
    finally:
        from ..core.cdp import close_all_sessions
        close_all_sessions()

    ctx.merge_handoff(handoff, by="visor", refs=[])
    arts = handoff.get("artifacts", {}) or {}
    tokens = arts.get("tokens") or []
    notes = arts.get("notes") or []
    trace = arts.get("trace") or []            # not standard; trace paths live on the visual-driver state records
    success = bool(tokens) or bool(ctx.landscape["identities"].get("A"))

    debug_print(f"\nvisor :: login {'SUCCEEDED' if success else 'did NOT succeed'} for {base_url}")
    if ex._trace and os.path.isdir(ex._trace):
        shots = sorted(f for f in os.listdir(ex._trace) if f.endswith(".png"))
        debug_print(f"visor :: {len(shots)} action screenshot(s) saved to {ex._trace}")
    for n in notes[-6:]:
        debug_print(f"  note: {n}")

    summary = {"login": "success" if success else "failed", "url": base_url,
               "session_token_captured": bool(tokens), "trace_dir": ex._trace, "notes": notes}
    print(json.dumps({"success": True, "kind": "items", "data": [summary], "error": None},
                     ensure_ascii=False, indent=2))
    return 0

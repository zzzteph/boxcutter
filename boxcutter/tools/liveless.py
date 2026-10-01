"""liveless - is a host reachable from the PUBLIC internet?

boxcutter runs where YOU are, so a target that looks dead to you may be firewalled to your egress, not actually
down (or the reverse). This asks an external vantage point - the liveless.shrewdeye.app probe - and reports one
record per host: ``{url, alive, message}``. Requests-only; one GET per target, run in parallel.

    boxcutter liveless example.com
    boxcutter liveless --list hosts.txt --table
"""
from __future__ import annotations

import concurrent.futures

import requests

from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result

NAME = "liveless"
KIND = "items"
HELP = ("Check if a host is reachable from the public internet (via the liveless.shrewdeye.app probe) -> "
        "{url, alive, message} per host.")

_DEFAULT_ENDPOINT = "https://liveless.shrewdeye.app/"


def add_arguments(parser) -> None:
    parser.add_argument("target", nargs="?", default=None, help="URL or host to check (or use --list)")
    parser.add_argument("--list", dest="listfile", default=None, metavar="FILE",
                        help="File of URLs/hosts to check, one per line (# comments and blank lines ignored)")
    parser.add_argument("--endpoint", default=_DEFAULT_ENDPOINT, metavar="URL",
                        help=f"liveless probe base URL (default {_DEFAULT_ENDPOINT})")
    parser.add_argument("--timeout", type=int, default=20, help="Per-check timeout in seconds (default 20)")
    parser.add_argument("--concurrency", type=int, default=10, help="Parallel checks (default 10)")
    add_common_args(parser)


def _check(endpoint: str, url: str, timeout: int) -> dict:
    """One probe: GET <endpoint>?url=<url> and normalise to {url, alive, message}. A transport failure is
    reported as a record (alive False) rather than raising, so one bad host never aborts a --list run."""
    try:
        r = requests.get(endpoint, params={"url": url}, timeout=timeout)
        j = r.json() if r.content else {}
        if isinstance(j, dict) and "alive" in j:
            return {"url": j.get("url") or url, "alive": bool(j.get("alive")),
                    "message": str(j.get("message", "") or "")}
        return {"url": url, "alive": False, "message": f"unexpected response (HTTP {r.status_code})"}
    except requests.RequestException as exc:
        return {"url": url, "alive": False, "message": f"probe request failed: {exc}"}
    except ValueError as exc:                                   # non-JSON body
        return {"url": url, "alive": False, "message": f"probe returned non-JSON: {exc}"}


def run(args) -> int:
    dbg = debug_logger(args.debug)
    targets: list[str] = []
    if args.target:
        targets.append(args.target.strip())
    if args.listfile:
        try:
            with open(args.listfile, encoding="utf-8") as fh:
                targets += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
        except OSError as exc:
            output_result([], args.output, f"could not read --list file: {exc}")
            return 1
    targets = list(dict.fromkeys(targets))                      # de-dupe, keep order
    if not targets:
        output_result([], args.output, "give a target URL/host, or --list FILE")
        return 1

    endpoint = (args.endpoint or "").strip() or _DEFAULT_ENDPOINT
    results: list = [None] * len(targets)
    workers = max(1, min(int(args.concurrency or 1), 50))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_check, endpoint, t, args.timeout): i for i, t in enumerate(targets)}
        for fut in concurrent.futures.as_completed(futs):
            rec = fut.result()
            results[futs[fut]] = rec                            # index-keyed, so output keeps input order
            dbg(f"liveless: {rec['url']} alive={rec['alive']} ({rec['message']})")

    output_result(results, args.output)
    return 0

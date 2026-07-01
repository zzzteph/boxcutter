"""fuzz - parameter / path / numeric-ID fuzzer.

An explicit marker in the target (or body) picks the mode:

  ``{NUMBERS}`` / ``{NUMBERS[m-n]}``   numeric-ID probing (IDOR enumeration)
  ``{FUZZ}`` in the URL or ``--data``  inject security payloads at that position
  (no marker, URL has query params)    inject every query parameter
  (no marker, ID-like path segments)   inject each numeric/UUID/long-hex segment

Detection is signal-based, not blind. Static error/output patterns (SQLi error,
LFI, RCE, NoSQL, error-disclosure, ...) are diffed against a per-parameter
baseline response, so a pattern that already matches the unfuzzed page (e.g. a JS
snippet that looks like an error string) is not reported - only an occurrence the
baseline did not have counts. Dynamic payloads (``{RANDOM}`` reflection, ``EXPR``
evaluation) are re-fired to weed out flukes - a fast-confirm path (shot 1 hits ->
2 more, need >=2/3) or the full ``>=4/5``. Time-based blind payloads are confirmed
only when the response time scales monotonically with the injected delay. Numeric
probing filters soft-404s with UUID canaries and dedupes bodies / redirect targets.
"""

from __future__ import annotations

import hashlib
import random
import re
import statistics
import time
import uuid
from collections import Counter
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url
from ..data.payloads import all_payloads

NAME = "fuzz"
KIND = "findings"
HELP = "Fuzz params/path/body for injection (XSS, SQLi, SSTI, LFI, RCE, XXE, NoSQL, GraphQL) or enumerate IDs."

# Classes run in inject mode, in report order.
INJECT_CLASSES = ["sqli", "rce", "ssti", "lfi", "xxe", "xss", "nosql", "errdisclosure", "graphql"]

# Severity per finding class (numeric/IDOR candidates and disclosure flag for review).
_SEVERITY = {
    "sqli": "high", "rce": "high", "ssti": "high", "lfi": "high",
    "xxe": "high", "xss": "high", "nosql": "high",
    "graphql": "medium", "errdisclosure": "medium", "numeric": "medium",
}

# Numeric mode -----------------------------------------------------------------
CANARY_COUNT = 3
SOFT404_MARGIN = 20
_NUMBERS_RANGE_RE = re.compile(r"\{NUMBERS\[(\d+)-(\d+)\]\}")
_NUMBERS_DEFAULT = ["-1", "0", "1", "2", "3", "5", "10", "50",
                    "100", "500", "999", "1000", "9999", "99999"]

# Auto fuzz-point detection on plain URLs --------------------------------------
_ID_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_ID_NUM = re.compile(r"^\d+$")
_ID_HEX = re.compile(r"^[0-9a-f]{20,}$", re.I)  # MongoDB ObjectID etc.

# Inject-mode reliability / timing tunables ------------------------------------
RELIABILITY_MIN = 4          # of 5 shots when shot 1 misses
TIME_VALUES = [1, 3, 5]      # injected sleep seconds, in order
TIME_MIN_SCALING = 3.0       # delta(last) - delta(first) must reach this many seconds
TIME_MIN_TRANSITIONS = 2     # how many of the deltas must increase step-to-step


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL; mark a position with {FUZZ} or {NUMBERS}, "
                                       "or leave unmarked to inject all query params")
    parser.add_argument("--method", default="GET", help="HTTP method (GET or POST)")
    parser.add_argument("--data", default=None, metavar="BODY",
                        help="Request body; put {FUZZ} where the payload goes")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Extra header (repeatable)")
    parser.add_argument("--status", default="200,201,204,301,302,307",
                        help="Status codes to report in numeric mode (default excludes 401/403/5xx)")
    parser.add_argument("--timeout", type=int, default=300, help="Max total seconds to spend fuzzing")
    parser.add_argument("--payload", action="append", default=[], metavar="PAYLOAD",
                        help="Send ONLY this exact payload at {FUZZ} (repeatable); skips the built-in payload set")
    parser.add_argument("--payload-file", default=None, metavar="FILE",
                        help="Read payloads to send at {FUZZ}, one per line")
    parser.add_argument("--pattern", default=None, metavar="REGEX",
                        help="With --payload: report a hit only when this regex matches the response "
                             "(no --pattern: just send each payload and report what came back)")
    add_common_args(parser)


def run(args) -> int:
    target = args.target.strip()
    method = args.method.strip().upper()

    try:
        keep = {int(s) for s in args.status.split(",") if s.strip()}
    except ValueError:
        output_result([], args.output, f"Invalid --status: {args.status!r}")
        return 1

    extra_headers = _parse_headers(args.header)
    dbg = debug_logger(args.debug)
    sess = http.session(extra_headers or None)
    deadline = time.time() + max(1, args.timeout)

    # Custom-payload mode: user supplies the exact payload(s) to send at {FUZZ}.
    payloads = _collect_payloads(args)
    if payloads is None:
        output_result([], args.output, f"Cannot read --payload-file: {args.payload_file!r}")
        return 1
    if payloads:
        # Same fuzz points as default mode (explicit {FUZZ}, query params, or
        # auto-derived ID path segments) - just with YOUR payload/pattern.
        custom: list[dict] = []
        for resolved in _auto_fuzz_targets(target):
            if time.time() >= deadline:
                break
            if not is_valid_url(resolved):
                output_result([], args.output, "Invalid URL.")
                return 1
            custom += _run_custom_mode(method, resolved, args.data, payloads, args.pattern, sess, deadline, dbg)
        dbg(f"Found {len(custom)} finding(s).")
        output_result(custom, args.output)
        return 0

    findings: list[dict] = []
    for resolved in _auto_fuzz_targets(target):
        if time.time() >= deadline:
            dbg(f"Timeout of {args.timeout}s reached, stopping.")
            break
        if not is_valid_url(resolved):
            output_result([], args.output, "Invalid URL.")
            return 1
        if _detect_mode(resolved) == "numeric":
            findings += _run_numeric_mode(resolved, keep, sess, deadline, dbg)
        else:
            findings += _run_inject_mode(method, resolved, args.data, sess, deadline, dbg)

    dbg(f"Found {len(findings)} finding(s).")
    output_result(findings, args.output)
    return 0


# -- mode detection / target derivation ---------------------------------------

def _detect_mode(target: str) -> str:
    if _NUMBERS_RANGE_RE.search(target) or "{NUMBERS}" in target:
        return "numeric"
    return "inject"


def _auto_fuzz_targets(url: str) -> list[str]:
    """Derive fuzz target(s) from the input URL.

    Explicit marker or query params -> use as-is. Otherwise, path segments that
    look like IDs (digits, UUID, long hex) each become one ``{FUZZ}`` variant so
    injection lands in the path. No fuzz point -> the URL unchanged (inject mode
    then finds nothing and returns empty)."""
    if "{FUZZ}" in url or "{NUMBERS}" in url or _NUMBERS_RANGE_RE.search(url):
        return [url]
    parsed = urlparse(url)
    if parsed.query:
        return [url]
    segments = parsed.path.split("/")
    targets: list[str] = []
    for i, seg in enumerate(segments):
        if _ID_UUID.match(seg) or _ID_NUM.match(seg) or _ID_HEX.match(seg):
            new_segs = segments[:]
            new_segs[i] = "{FUZZ}"
            targets.append(urlunparse(parsed._replace(path="/".join(new_segs))))
    return targets or [url]


# -- numeric mode (IDOR enumeration) ------------------------------------------

def _build_numeric_words(target: str) -> tuple[list[str], str]:
    m = _NUMBERS_RANGE_RE.search(target)
    if m:
        start, end = int(m.group(1)), int(m.group(2))
        return [str(i) for i in range(start, end + 1)], m.group(0)
    return list(_NUMBERS_DEFAULT), "{NUMBERS}"


class _Soft404Filter:
    """Body-size baseline from UUID canary probes; flags responses that match it."""

    def __init__(self, template: str, marker: str, sess) -> None:
        sizes = []
        for _ in range(CANARY_COUNT):
            url = template.replace(marker, uuid.uuid4().hex)
            resp = http.send("GET", url, sess=sess, allow_redirects=False, timeout=10)
            if resp["error"] is None and resp["status"] is not None:
                sizes.append(resp["body_bytes"])
        self._active = bool(sizes)
        if sizes:
            self._median = statistics.median(sizes)
            self._window = (max(sizes) - min(sizes)) + SOFT404_MARGIN

    def is_soft404(self, size: int) -> bool:
        return self._active and abs(size - self._median) <= self._window


def _run_numeric_mode(target: str, keep: set[int], sess, deadline: float, dbg) -> list[dict]:
    words, marker = _build_numeric_words(target)
    soft404 = _Soft404Filter(target, marker, sess)
    found: list[dict] = []
    seen: set[str] = set()
    for value in words:
        if time.time() >= deadline:
            break
        url = target.replace(marker, value)
        resp = http.send("GET", url, sess=sess, allow_redirects=False, timeout=10)
        if resp["error"] is not None or resp["status"] not in keep:
            continue
        if soft404.is_soft404(resp["body_bytes"]):
            continue
        if resp["status"] in (301, 302, 307, 308):
            dedup_key = "redir:" + resp["headers"].get("Location", resp["body"][:80])
        else:
            dedup_key = hashlib.md5(resp["body"].encode("utf-8", errors="replace")).hexdigest()
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        ct = resp["headers"].get("Content-Type", "").split(";")[0].strip()
        dbg(f"  [numeric] id {value} -> {resp['status']} {resp['body_bytes']}b")
        found.append(_numeric_finding(url, value, resp, ct))
    return found


# -- inject mode ---------------------------------------------------------------

def _group_payloads() -> tuple[dict[str, list], dict[str, list]]:
    """Group ``all_payloads()`` by class; split ``{TIME}`` payloads into time-based."""
    pattern_based: dict[str, list] = {}
    time_based: dict[str, list] = {}
    for entry in all_payloads():
        cls = entry["class"]
        if "{TIME}" in entry["payload"]:
            time_based.setdefault(cls, []).append(entry["payload"])
        else:
            pattern_based.setdefault(cls, []).append((entry["payload"], entry.get("pattern")))
    return pattern_based, time_based


def _random_expr() -> tuple[str, str]:
    """A random product that is always 6 digits, so the result is as unlikely to
    coincide with existing page content as a 6-digit {RANDOM}."""
    while True:
        a, b = random.randint(317, 999), random.randint(317, 999)
        if a != b and 100_000 <= a * b <= 999_999:
            return f"{a}*{b}", str(a * b)


def _resolve_one(payload_raw: str, pattern_raw: str | None) -> tuple[str, str | None]:
    """Resolve {RANDOM} / EXPR markers, mirroring the substitution into the pattern."""
    if "{RANDOM}" in payload_raw:
        rand_val = str(random.randint(100_000, 999_999))
        payload = payload_raw.replace("{RANDOM}", rand_val)
        pattern = pattern_raw.replace("{RANDOM}", rand_val) if pattern_raw else None
    elif "EXPR" in payload_raw:
        expr_str, result = _random_expr()
        payload = payload_raw.replace("EXPR", expr_str)
        pattern = pattern_raw.replace("{EXPR_VALUE}", result) if pattern_raw else None
    else:
        payload, pattern = payload_raw, pattern_raw
    return payload, pattern


def _needs_reliability(payload_raw: str) -> bool:
    return "{RANDOM}" in payload_raw or "EXPR" in payload_raw


# Percent-encode a payload placed at a {FUZZ} position in the URL, treating the
# slot as one component value. Everything is encoded - including ``/`` - so the
# payload stays inside its own path segment (or query value) instead of spilling
# into the URL structure (a raw ``/`` would start a new segment, ``#``/``?`` would
# become a fragment/query). ``%`` is left literal so an already-encoded payload
# (e.g. %252e%252e%2f, %00) is sent as authored rather than double-encoded.
_FUZZ_SAFE = "%"


def _substitute(method, url, body, param, payload, sess):
    """Place ``payload`` at ``param`` (URL marker, body marker, or a query param)
    and send. Returns the normalized response dict with the request URL added."""
    new_url, new_body = url, body
    if param == "__URL_FUZZ__":
        new_url = url.replace("{FUZZ}", quote(payload, safe=_FUZZ_SAFE))
    elif param == "__BODY_FUZZ__":
        new_body = (body or "").replace("{FUZZ}", payload)
    else:
        parsed = urlparse(url)
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        new_url = urlunparse(parsed._replace(query=urlencode(
            [(k, payload if k == param else v) for k, v in qs])))
    resp = http.send(method, new_url, sess=sess, data=new_body, timeout=15, allow_redirects=False)
    resp["_url"] = new_url
    return resp


def _param_targets(url: str, body) -> list[str]:
    if "{FUZZ}" in url:
        return ["__URL_FUZZ__"]
    if body and "{FUZZ}" in str(body):
        return ["__BODY_FUZZ__"]
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def _match(pattern: str, body: str):
    try:
        return re.search(pattern, body, re.I)
    except re.error:
        return None


# -- custom-payload mode (bring your own payloads) ----------------------------

def _collect_payloads(args) -> list[str] | None:
    """Gather --payload values + --payload-file lines. None on a file error."""
    payloads = list(getattr(args, "payload", None) or [])
    path = getattr(args, "payload_file", None)
    if path:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                payloads += [line.rstrip("\r\n") for line in fh if line.strip()]
        except OSError:
            return None
    return payloads


def _param_label(param: str) -> str:
    return {"__URL_FUZZ__": "FUZZ", "__BODY_FUZZ__": "body"}.get(param, param)


def _run_custom_mode(method, target, body, payloads, pattern, sess, deadline, dbg) -> list[dict]:
    """Send each user-supplied payload at the fuzz point. With ``pattern``, report
    only responses the regex matches; without it, report what each payload returned."""
    points = _param_targets(target, body)
    if not points:
        dbg(f"No fuzz point ({{FUZZ}} or query param) in {target}")
        return []
    findings: list[dict] = []
    for param in points:
        label = _param_label(param)
        matched: list[tuple] = []
        sent: list[tuple] = []
        for payload in payloads:
            if time.time() >= deadline:
                dbg("Timeout reached, stopping.")
                break
            resp = _substitute(method, target, body, param, payload, sess)
            if resp["error"] is not None:
                dbg(f"  [custom] {label} <= {payload!r} -> error: {resp['error']}")
                continue
            status, nbytes = resp["status"], resp["body_bytes"]
            dbg(f"  [custom] {label} <= {payload!r} -> {status} {nbytes}b")
            if pattern:
                m = _match(pattern, resp["body"] or "")
                if m:
                    matched.append((payload, m.group(0)[:200], resp["_url"], status))
            else:
                snippet = " ".join((resp["body"] or "")[:200].split())
                sent.append((payload, status, nbytes, snippet, resp["_url"]))
        if pattern and matched:
            findings.append(_custom_match_finding(method, label, pattern, matched))
        elif not pattern and sent:
            findings.append(_custom_sent_finding(method, label, sent))
    return findings


def _custom_match_finding(method, label, pattern, matched) -> dict:
    lines = [f"Pattern:  {pattern}", f"Param:    {label}", f"Matched ({len(matched)}):"]
    lines += [f"  - {p}  =>  [{st}] {ev}" for p, ev, _u, st in matched[:50]]
    return {"severity": "high", "info": "\n".join(lines), "url": matched[0][2],
            "title": f"[{method}] [custom-match] in '{label}' ({len(matched)} matched)"}


def _custom_sent_finding(method, label, sent) -> dict:
    lines = [f"Param:    {label}", f"Sent {len(sent)} payload(s):"]
    lines += [f"  - {p}  =>  [{st}] {n}b  {snip}" for p, st, n, snip, _u in sent[:50]]
    return {"severity": "info", "info": "\n".join(lines), "url": sent[0][4],
            "title": f"[{method}] [custom] sent {len(sent)} payload(s) to '{label}'"}


def _new_match(pattern: str, body: str, baseline_body: str, cache: dict):
    """Return a match of ``pattern`` in ``body`` that the baseline did not already
    contain - i.e. an occurrence beyond what the unfuzzed page had.

    Suppresses false positives where a static error/output regex matches content
    that is part of the normal page (e.g. a minified JS snippet that contains
    ``TypeError ... is not a function``). Matched strings are counted, so a
    payload that makes an existing pattern appear an *extra* time still reports.
    ``cache`` memoizes the baseline match counts per pattern (one body per param).
    """
    try:
        rx = re.compile(pattern, re.I)
    except re.error:
        return None
    base = cache.get(pattern)
    if base is None:
        base = Counter(m.group(0) for m in rx.finditer(baseline_body))
        cache[pattern] = base
    seen: Counter = Counter()
    for m in rx.finditer(body):
        text = m.group(0)
        seen[text] += 1
        if seen[text] > base.get(text, 0):
            return m
    return None


def _check_signal_reliable(method, url, body, param, payload_raw, pattern_raw, sess):
    """Re-fire a dynamic payload to confirm. Shot 1 hit -> 2 more, need >=2/3;
    shot 1 miss -> 4 more, need >=4/5. Returns (ok, signal, evidence, payload, url, status)."""
    state = {"signal": None, "evidence": None, "payload": None, "url": url, "status": None}

    def _shot() -> bool:
        payload, pattern = _resolve_one(payload_raw, pattern_raw)
        resp = _substitute(method, url, body, param, payload, sess)
        if resp["error"] is not None or resp["status"] is None or not pattern:
            return False
        m = _match(pattern, resp["body"])
        if not m:
            return False
        state.update(signal="pattern_match", evidence=m.group(0)[:200],
                     payload=payload, url=resp["_url"], status=resp["status"])
        return True

    if _shot():
        hits = 1 + sum(1 for _ in range(2) if _shot())
        ok = hits >= 2
    else:
        hits = sum(1 for _ in range(4) if _shot())
        ok = hits >= RELIABILITY_MIN
    return (ok, state["signal"], state["evidence"], state["payload"], state["url"], state["status"])


def _check_time_reliable(method, url, body, param, payload_template, baseline_time, sess):
    """Fire one shot per TIME value; confirm only if response time scales with TIME."""
    deltas: list[float] = []
    last_url, last_status = url, None
    for t in TIME_VALUES:
        payload = payload_template.replace("{TIME}", str(t))
        resp = _substitute(method, url, body, param, payload, sess)
        if resp["error"] is not None or resp["status"] is None:
            return False, None, None, last_url, last_status
        last_url, last_status = resp["_url"], resp["status"]
        deltas.append(resp["time_ms"] / 1000.0 - baseline_time)

    scaling = deltas[-1] - deltas[0]
    transitions = sum(1 for i in range(1, len(deltas)) if deltas[i] > deltas[i - 1])
    if scaling >= TIME_MIN_SCALING and transitions >= TIME_MIN_TRANSITIONS:
        evidence = ", ".join(f"T={t}s->{d:+.1f}s" for t, d in zip(TIME_VALUES, deltas))
        return True, "time_scaling", evidence, last_url, last_status
    return False, None, None, last_url, last_status


def _run_inject_mode(method, target, body, sess, deadline: float, dbg) -> list[dict]:
    params = _param_targets(target, body)
    if not params:
        dbg(f"No fuzzable parameter in {target}")
        return []

    pattern_based, time_based = _group_payloads()
    # Collect confirmed hits per (param, class) so one vulnerable parameter yields a
    # single finding listing every payload that worked - not 5-10 near-duplicate rows.
    hits: dict[tuple[str, str], list[dict]] = {}
    out_of_time = False

    for param in params:
        if out_of_time or time.time() >= deadline:
            break
        baseline = _substitute(method, target, body, param, "control-x9z3-marker", sess)
        if baseline["error"] is not None or baseline["status"] is None:
            continue
        baseline_time = baseline["time_ms"] / 1000.0
        baseline_body = baseline["body"]
        baseline_cache: dict = {}  # pattern -> Counter of baseline matches
        label = "FUZZ" if param in ("__URL_FUZZ__", "__BODY_FUZZ__") else param

        for cls in INJECT_CLASSES:
            for payload_raw, pattern_raw in pattern_based.get(cls, []):
                if time.time() >= deadline:
                    dbg(f"Timeout reached, stopping at [{cls}] on '{label}'.")
                    out_of_time = True
                    break
                if _needs_reliability(payload_raw):
                    ok, signal, evidence, payload, url, status = _check_signal_reliable(
                        method, target, body, param, payload_raw, pattern_raw, sess)
                else:
                    payload, pattern = _resolve_one(payload_raw, pattern_raw)
                    resp = _substitute(method, target, body, param, payload, sess)
                    ok = signal = evidence = url = status = None
                    if resp["error"] is None and resp["status"] is not None and pattern:
                        # Diff against the baseline: only a match the unfuzzed page
                        # did not already have counts as a signal.
                        m = _new_match(pattern, resp["body"], baseline_body, baseline_cache)
                        if m:
                            ok, signal, evidence = True, "pattern_match", m.group(0)[:200]
                            url, status = resp["_url"], resp["status"]
                if ok:
                    dbg(f"  Confirmed [{cls}] in '{label}': {signal}")
                    hits.setdefault((label, cls), []).append(
                        {"payload": payload, "signal": signal, "evidence": evidence,
                         "url": url, "status": status})
            if out_of_time:
                break

            for payload_template in time_based.get(cls, []):
                if time.time() >= deadline:
                    out_of_time = True
                    break
                ok, signal, evidence, url, status = _check_time_reliable(
                    method, target, body, param, payload_template, baseline_time, sess)
                if ok:
                    dbg(f"  Confirmed time-based [{cls}] in '{label}'")
                    hits.setdefault((label, cls), []).append(
                        {"payload": payload_template.replace("{TIME}", str(TIME_VALUES[-1])),
                         "signal": signal, "evidence": evidence, "url": url, "status": status})
            if out_of_time:
                break

    return [_grouped_finding(method, cls, param, hs) for (param, cls), hs in hits.items()]


# -- finding builders (boxcutter {severity, title, info, url} shape) ----------

def _grouped_finding(method, cls, param, hits: list[dict]) -> dict:
    """One finding per (param, class), listing every confirmed payload as evidence."""
    first = hits[0]
    n = len(hits)
    lines = [
        f"Class:    {cls}",
        f"Param:    {param}",
        f"Signal:   {first['signal']}",
        f"Status:   {first['status']}",
        f"URL:      {first['url']}",
        f"Confirmed payloads ({n}):",
    ]
    for h in hits:
        evidence = (h["evidence"] or "").replace("\n", " ")[:100]
        lines.append(f"  - {h['payload']}  =>  {evidence}")
    return {
        "severity": _SEVERITY.get(cls, "medium"),
        "title": f"[{method}] [{cls}] in '{param}' ({n} payload{'s' if n != 1 else ''})",
        "info": "\n".join(lines),
        "url": first["url"] or "",
    }


def _numeric_finding(url, value, resp, content_type) -> dict:
    return {
        "severity": _SEVERITY["numeric"],
        "title": f"[numeric] id {value} returns a distinct response",
        "info": "\n".join([
            "Class:    numeric",
            "Param:    path",
            f"Payload:  {value}",
            "Signal:   non-soft-404",
            f"Evidence: {resp['status']} {content_type} {resp['body_bytes']}b",
            f"Status:   {resp['status']}",
            f"URL:      {url}",
        ]),
        "url": url,
    }


def _parse_headers(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in raw_headers or []:
        if ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        if name.strip():
            headers[name.strip()] = value.strip()
    return headers

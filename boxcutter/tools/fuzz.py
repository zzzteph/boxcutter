"""fuzz - reflection/injection parameter fuzzer. Port of app:fuzz (FuzzScan).

Fuzzes query/body params (or a ``{FUZZ}`` path placeholder) with the payload
table, confirming reflections (XSS/SSTI/SQLi-error/LFI/RCE/XXE) and time-based
blind injections. Dynamic payloads (random/expression) require 4/5 confirming
hits; timing payloads use a baseline + scaled-delay confirm.
"""

from __future__ import annotations

import math
import re
import shlex
import time
from urllib.parse import parse_qsl, urlencode, urlparse

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.rand import random_string
from ..core.validators import is_valid_url
from ..data.payloads import all_payloads

NAME = "fuzz"
KIND = "findings"
HELP = "Fuzz URL/body parameters for reflection vulns (XSS, SSTI, SQLi, LFI, RCE, XXE)."

_CHROME_UA = http.CHROME_UA


def add_arguments(parser) -> None:
    parser.add_argument("target", help="Target URL (mark params with FUZZ token, or fuzz all)")
    parser.add_argument("--method", default="GET", help="HTTP method (GET or POST)")
    parser.add_argument("--data", default=None, help="Raw POST body (form-encoded or JSON)")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Extra header (repeatable)")
    parser.add_argument("--timeout", type=int, default=300, help="Max total seconds to spend fuzzing")
    add_common_args(parser)


def run(args) -> int:
    ctx = _Fuzzer(args)
    return ctx.execute()


class _Fuzzer:
    def __init__(self, args) -> None:
        self.args = args
        self.dbg = debug_logger(args.debug)
        self.custom_headers = self._parse_headers(args.header)
        self.started_at = time.time()
        self.timeout = args.timeout

    def execute(self) -> int:
        args = self.args
        target = args.target.strip()
        method = args.method.strip().upper()
        raw_data = args.data

        if not is_valid_url(target):
            output_result([], args.output, "Invalid URL.")
            return 1

        parsed = urlparse(target)
        port = f":{parsed.port}" if parsed.port else ""
        base = f"{parsed.scheme or 'http'}://{parsed.hostname or ''}{port}{parsed.path}"
        query_string = f"?{parsed.query}" if parsed.query else ""

        encoding = "form"
        if raw_data:
            encoding = "json" if raw_data.lstrip().startswith("{") else "form"
            all_params = _json_loads(raw_data) if encoding == "json" else dict(parse_qsl(raw_data, keep_blank_values=True))
        else:
            all_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

        path_fuzz = "{FUZZ}" in base
        if path_fuzz:
            params_to_fuzz = ["__path__"]
        else:
            if not all_params:
                self.dbg("No parameters found, nothing to fuzz.")
                output_result([], args.output)
                return 0
            has_marker = any(isinstance(v, str) and "{FUZZ}" in v for v in all_params.values())
            if has_marker:
                params_to_fuzz = [k for k, v in all_params.items() if isinstance(v, str) and "{FUZZ}" in v]
            else:
                params_to_fuzz = list(all_params.keys())

        findings: list[dict] = []
        seen: set[str] = set()
        payloads = all_payloads()

        stop = False
        for param in params_to_fuzz:
            if stop:
                break
            for defn in payloads:
                if defn.get("pattern_type") == "timing":
                    dedupe_key = f"{defn['class']}|{param}|{defn['payload']}"
                    if dedupe_key in seen:
                        continue
                    if self._timed_out():
                        self.dbg(f"Timeout of {self.timeout}s reached, stopping.")
                        stop = True
                        break
                    finding = self._attempt_timing(defn, param, all_params, method, encoding, base, query_string)
                    if finding is not None:
                        seen.add(dedupe_key)
                        findings.append(finding)
                    continue

                dynamic = self._is_dynamic(defn)
                attempts = 5 if dynamic else 1
                required = 4 if dynamic else 1
                hits = 0
                evidence = None

                broke_global = False
                for i in range(attempts):
                    if self._timed_out():
                        self.dbg(f"Timeout of {self.timeout}s reached, stopping.")
                        stop = True
                        broke_global = True
                        break
                    try:
                        r = self._send_one(defn, param, all_params, method, encoding, base, query_string)
                    except Exception as exc:  # noqa: BLE001
                        self.dbg(f"Request failed: {exc}")
                        continue
                    self.dbg(f"Trying [{defn['class']}] on param '{param}' (#{i + 1}): {r['payload']}")
                    matched = (
                        self._match_response(r["body"], r["needle"], defn)
                        and (defn["class"] != "XSS" or r["payload"] in r["body"])
                        and (defn["class"] != "XSS" or "text/html" in r["contentType"].lower())
                    )
                    if matched:
                        hits += 1
                        evidence = r
                        continue
                    if i == 0:
                        break

                if broke_global:
                    break
                if hits < required or evidence is None:
                    continue

                finding = self._build_reflection_finding(defn, param, method, base, evidence, hits, attempts)
                dedupe_key = f"{defn['class']}|{param}|{defn['payload']}"
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                self.dbg(f"  Confirmed [{defn['class']}] in '{param}' ({hits}/{attempts})")
                findings.append(finding)

        self.dbg(f"Found {len(findings)} reflection(s).")
        output_result(findings, args.output)
        return 0

    # -- request senders -------------------------------------------------
    def _headers(self) -> dict[str, str]:
        return {"User-Agent": _CHROME_UA, **self.custom_headers}

    def _send(self, method: str, url: str, *, params=None, json=None, timeout: int = 10):
        return http.request(
            method, url, headers=self._headers(), data=None if json is not None else params,
            json=json, params=None, timeout=timeout, verify=False,
        )

    def _send_one(self, defn, param, all_params, method, encoding, base, query_string) -> dict:
        payload, needle = self._resolve_payload(defn)

        if param == "__path__" or "{FUZZ}" in base:
            from urllib.parse import quote

            fuzzed_base = base.replace("{FUZZ}", quote(payload, safe=""))
            if query_string:
                request_url = fuzzed_base + query_string
            elif all_params:
                request_url = fuzzed_base + "?" + urlencode(all_params)
            else:
                request_url = fuzzed_base
            curl = f"curl -sk -X {method} {shlex.quote(request_url)}"
            if method == "POST":
                response = self._send("POST", request_url, params=all_params)
            else:
                response = self._send("GET", request_url)
            return self._wrap(payload, needle, response, request_url, curl)

        fuzzed = {**all_params, param: payload}
        if method == "POST":
            request_url = base + query_string
            if encoding == "json":
                curl = (
                    "curl -sk -X POST -H 'Content-Type: application/json' -d "
                    + shlex.quote(_json_dumps(fuzzed)) + " " + shlex.quote(request_url)
                )
                response = self._send("POST", request_url, json=fuzzed)
            else:
                curl = "curl -sk -X POST -d " + shlex.quote(urlencode(fuzzed)) + " " + shlex.quote(request_url)
                response = self._send("POST", request_url, params=fuzzed)
        else:
            request_url = base + "?" + urlencode(fuzzed)
            curl = "curl -sk " + shlex.quote(request_url)
            response = self._send("GET", request_url)

        return self._wrap(payload, needle, response, request_url, curl)

    @staticmethod
    def _wrap(payload, needle, response, request_url, curl) -> dict:
        return {
            "payload": payload,
            "needle": needle,
            "body": response.text,
            "contentType": response.headers.get("Content-Type", ""),
            "requestUrl": request_url,
            "curlExpr": curl,
        }

    def _send_timed(self, all_params, param, payload, method, encoding, base, query_string, timeout) -> dict | None:
        params = {**all_params}
        if payload is not None:
            params[param] = payload

        if method == "POST":
            request_url = base + query_string
            if encoding == "json":
                curl = (
                    f"curl -sk --max-time {timeout} -X POST -H 'Content-Type: application/json' -d "
                    + shlex.quote(_json_dumps(params)) + " " + shlex.quote(request_url)
                )
            else:
                curl = (
                    f"curl -sk --max-time {timeout} -X POST -d "
                    + shlex.quote(urlencode(params)) + " " + shlex.quote(request_url)
                )
        else:
            request_url = base + "?" + urlencode(params)
            curl = f"curl -sk --max-time {timeout} " + shlex.quote(request_url)

        start = time.time()
        try:
            if method == "POST":
                if encoding == "json":
                    self._send("POST", request_url, json=params, timeout=timeout)
                else:
                    self._send("POST", request_url, params=params, timeout=timeout)
            else:
                self._send("GET", request_url, timeout=timeout)
        except Exception:  # noqa: BLE001
            return None

        return {"elapsed": time.time() - start, "requestUrl": request_url, "curlExpr": curl}

    # -- timing detection ------------------------------------------------
    def _attempt_timing(self, defn, param, all_params, method, encoding, base, query_string) -> dict | None:
        delay = max(1, int(defn.get("delay", 5)))
        margin = 1.5

        baseline = self._send_timed(all_params, param, None, method, encoding, base, query_string, 15)
        if baseline is None:
            return None
        t_base = baseline["elapsed"]
        self.dbg(f"[{defn['class']}] timing baseline for '{param}': {t_base:.2f}s")
        if self._timed_out():
            return None

        probe_payload = defn["payload"].replace("{TIMEOUT}", str(delay))
        probe = self._send_timed(all_params, param, probe_payload, method, encoding, base, query_string,
                                 int(math.ceil(t_base + delay + 5)))
        if probe is None:
            return None
        self.dbg(f"[{defn['class']}] probe(delay={delay}s) for '{param}': {probe['elapsed']:.2f}s")
        if (probe["elapsed"] - t_base) < (delay - margin):
            return None
        if self._timed_out():
            return None

        delay2 = delay * 2
        confirm_payload = defn["payload"].replace("{TIMEOUT}", str(delay2))
        confirm = self._send_timed(all_params, param, confirm_payload, method, encoding, base, query_string,
                                   int(math.ceil(t_base + delay2 + 5)))
        if confirm is None:
            return None
        self.dbg(f"[{defn['class']}] confirm(delay={delay2}s) for '{param}': {confirm['elapsed']:.2f}s")
        if (confirm["elapsed"] - t_base) < (delay2 - margin):
            return None

        self.dbg(f"  Confirmed timing-based [{defn['class']}] in '{param}'")
        return {
            "title": f"[{method}] [{defn['class']}] time-based injection in '{param}'",
            "url": base,
            "severity": defn["severity"],
            "info": "\n".join(
                [
                    f"Parameter:    {param}",
                    f"Payload:      {confirm_payload}",
                    f"URL:          {confirm['requestUrl']}",
                    f"Curl:         {confirm['curlExpr']}",
                    f"Baseline:     {t_base:.2f}s",
                    f"Probe ({delay}s):    {probe['elapsed']:.2f}s",
                    f"Confirm ({delay2}s):  {confirm['elapsed']:.2f}s",
                ]
            ),
        }

    # -- reflection finding ----------------------------------------------
    def _build_reflection_finding(self, defn, param, method, base, evidence, hits, attempts) -> dict:
        body = evidence["body"]
        needle = evidence["needle"]
        payload = evidence["payload"]

        if defn.get("pattern_type", "string") == "regex":
            m = re.search(needle, body)
            pos = m.start() if m else 0
        else:
            pos = body.find(needle)
            if pos < 0:
                pos = 0
        start = max(0, pos - 60)
        context = re.sub(r"\s+", " ", body[start : start + 200])

        return {
            "title": f"[{method}] [{defn['class']}] [{payload}] reflected in '{param}'",
            "url": base,
            "severity": defn["severity"],
            "info": "\n".join(
                [
                    f"Parameter: {param}",
                    f"Payload:   {payload}",
                    f"URL:       {evidence['requestUrl']}",
                    f"Curl:      {evidence['curlExpr']}",
                    f"Confirmed: {hits}/{attempts} attempts",
                    f"Context:   ...{context}...",
                ]
            ),
        }

    # -- payload resolution / matching -----------------------------------
    @staticmethod
    def _is_dynamic(defn) -> bool:
        return "{RANDOM}" in defn["payload"] or "EXPRESSION" in defn["payload"]

    @staticmethod
    def _resolve_payload(defn) -> tuple[str, str]:
        template = defn["payload"]
        random = random_string(8)
        import secrets

        expr_a = secrets.randbelow(9000) + 1000
        expr_b = secrets.randbelow(9000) + 1000
        expr_str = f"{expr_a}*{expr_b}"
        expr_value = str(expr_a * expr_b)

        payload = template.replace("{RANDOM}", random).replace("EXPRESSION", expr_str)

        if "pattern" in defn:
            return payload, defn["pattern"].replace("{RANDOM}", random)
        if "{RANDOM}" in template:
            return payload, random
        result = defn.get("result", payload)
        if result == "EXPRESSION_VALUE":
            return payload, expr_value
        return payload, result

    @staticmethod
    def _match_response(body: str, needle: str, defn) -> bool:
        if defn.get("pattern_type", "string") == "regex":
            return re.search(needle, body) is not None
        return needle in body

    # -- misc ------------------------------------------------------------
    def _timed_out(self) -> bool:
        return (time.time() - self.started_at) >= self.timeout

    @staticmethod
    def _parse_headers(raw_headers: list[str]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for raw in raw_headers or []:
            if ":" not in raw:
                continue
            name, value = raw.split(":", 1)
            if name.strip():
                headers[name.strip()] = value.strip()
        return headers


def _json_loads(data: str):
    import json

    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {}


def _json_dumps(obj) -> str:
    import json

    return json.dumps(obj)

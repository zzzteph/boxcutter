"""vera - a PHASED, hypothesis-driven scanner with a validation GATE and a DEEPENING loop.

The harness drives fixed phases; the model is asked, in focused requests, to GENERATE ideas (so its thinking is
always returned and printed, even for a cheap model or one that hides its chain-of-thought):

  1. RECON      - run read-only tools, and EXPAND the surface: parse the OpenAPI spec + api-map + path-bust into
                  a concrete per-endpoint list (method + url) the model can target.
  2. AUTH       - if --creds are given, log in as a HYPOTHESIS: the model produces the login request, the harness
                  fires it, captures the session, and PROVES it (a gated endpoint answers as 'primary' but not
                  as 'anon'). Only then is the authenticated identity usable.
  3. HYPOTHESES - request JSON hypotheses (claim + rationale + checkable predicted_observable + the exact test
                  request, run as a named identity). Printed, always.
  4. VALIDATE   - the harness fires each request (+ its control) and GRADES the predicate: confirmed /
                  ruled_out / open_proof_gap. Nothing is self-attested.
  5. DEEPEN     - each round feeds the confirmed findings + the endpoint surface + the authed identity back in,
                  and asks for NEW, chained hypotheses (leaked creds -> login -> authed IDOR, per-endpoint
                  authz/injection). Bounded by --max-rounds; stops early when a round finds nothing new.

Reuses irvin's request primitive: provider.chat(system,user) -> extract_json. Design: docs/vera-design.md.

  boxcutter ai vera https://app.example.com --provider openai --model gpt-5 --max-rounds 8 --creds user:pass
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import time
from urllib.parse import urlparse

from ..core import agentlog, http
from ..core.envelope import output_result
from ..core.validators import is_valid_url
from ..irvin.context import extract_json
from ..tools import toolschema
from . import skills
from . import _zapproxy
from .provider import PROVIDERS, add_agent_args, make_provider

NAME = "vera"
KIND = "findings"
HELP = "Phased hypothesis scanner: recon+expand -> auth -> request hypotheses -> PROVE each -> deepen."

_RECON = [
    ("http-request", []),
    ("path-bust", ["--depth", "0"]),
    ("katana-crawl", ["--timeout", "20"]),
    ("graphql-detect", []),
    ("swagger-specs", []),
    ("api-map", []),
]

_PRED_KEYS = {"status_in", "body_contains", "body_not_contains", "differs_from_control",
              "control_status_in", "latency_ms_gte", "latency_ms_lt", "header_contains"}

# Independent proof-of-impact: a confirmation is only a real finding if the RESPONSE carries sensitive content,
# or it was proven by a differential/timing. A bare "200 + the page's own text" is an observation, not impact.
_SENSITIVE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY|-----BEGIN CERTIFICATE|BEGIN RSA|"
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{16,}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]+|"
    r"AIza[0-9A-Za-z_\-]{20,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}|"  # JWT
    r"DB_PASSWORD|DB_USERNAME|JWT_SECRET|APP_KEY|DATABASE_URL|SPRING_DATASOURCE|SECRET_KEY|AWS_SECRET|"
    r"\bpassword\s*[=:]\s*\S|api[_-]?key\s*[=:]\s*\S|"
    r"root:x:0:0:|/bin/bash\b|nologin\b|"                                        # /etc/passwd
    r"ref:\s*refs/heads/|\[remote \"|\[core\]|"                                  # git metadata
    r"SQLSTATE|SQL syntax|Unclosed quotation|unterminated quoted string|PDOException|ORA-\d{4}|"  # sql errors
    r"psql:|sqlite3?\.OperationalError|org\.hibernate|JDBCException|"
    r"Traceback \(most recent call last\)|at java\.[a-z]|at [\w.$]+\([\w.]+\.java:|"  # stack traces
    r"\"__schema\"|__schema\s*\{|propertySources|dispatcherServlet)", re.I)


def _impactful(pred: dict, primary: dict, control) -> bool:
    """True when a confirmation actually PROVES impact (not just re-observes recon): a differential vs a real
    control, a timing proof, or sensitive content in the response. Bare status/body-of-the-page is NOT impact."""
    if (pred.get("differs_from_control") or "control_status_in" in pred) and control is not None:
        return True
    if "latency_ms_gte" in pred:
        return True
    return bool(_SENSITIVE.search(primary.get("body") or ""))

_HYP_SYS = (
    "You are an offensive web pentester. Given RECON + a mapped ENDPOINT surface for ONE target, output attack "
    "HYPOTHESES that, if true, let an attacker DO something (read data they shouldn't, gain access, run code, "
    "escalate). Reply with JSON ONLY:\n"
    '{"plan": ["short ordered step", ...], "hypotheses": [ {\n'
    '  "claim": "...", "vuln_class": "sqli|idor|missing-auth|privesc|ssrf|lfi|rce|secrets|graphql|...",\n'
    '  "rationale": "WHY, from recon", "impact": "what an attacker GAINS if true (data/access/RCE)",\n'
    '  "severity": "critical|high|medium",\n'
    '  "test_request": {"method":"GET","url":"https://...","headers":{},"body":null},\n'
    '  "predicted_observable": { ...predicate... },\n'
    '  "control_request": {"method":"GET","url":"..."}, "as_identity": "anon|primary",\n'
    '  "control_identity": "anon",\n'
    '  "tool": "fuzz|sqlmap"   // OPTIONAL: run this boxcutter tool to PROVE/EXTRACT instead of one request\n'
    "} ] }\n\n"
    "predicted_observable is graded by code; ONLY these keys: status_in (list), body_contains (string, or list "
    "= ANY match), body_not_contains, differs_from_control (bool; needs control_request), control_status_in "
    "(list), latency_ms_gte, latency_ms_lt, header_contains (string in any header, or {name: substr}).\n\n"
    "HARD RULES:\n"
    "- An OBSERVATION IS NOT A HYPOTHESIS. 'X returns 200 with <its own title>' is a recon fact, not a finding. "
    "Never propose a hypothesis whose test just re-fetches a recon result and predicts the SAME content. A "
    "confirmation must beat the page's normal response: prove SENSITIVE content (a secret/token/PII/file marker "
    "like DB_PASSWORD=, -----BEGIN, root:x:0:0:, an SQL error, another user's data) OR a DIFFERENTIAL vs a "
    "control (differs_from_control + control_status_in) OR timing. A bare status_in+body_contains of the page's "
    "own text will be REJECTED as an observation.\n"
    "- The predicate must signal the VULN IS PRESENT; secure behaviour (401/403 on a gated route) is NOT a finding.\n"
    "- EXPLOIT, don't just detect. For injection set tool='sqlmap' (dump/extract) or 'fuzz' (self-confirming "
    "payload DB) so the finding is proven by real exploitation, not a guessed error string.\n"
    "- ESCALATE / MOVE LATERALLY every round: from each confirmed primitive take the NEXT HOP toward impact - "
    "SQLi -> dump creds -> log in -> authed IDOR/admin; a leaked .env/secret -> USE the credential/key; LFI -> "
    "read app config -> secrets -> auth; an admin action -> perform it. Chain toward data exfil, credential "
    "theft, auth bypass, account takeover, or RCE. Do NOT re-propose already-tested hypotheses.\n"
    "- Authz proofs run as_identity='primary' vs control_identity='anon' when a 'primary' identity exists.\n"
    "- A WRITE/state-change's 2xx is NOT proof - prove the effect by reading the resource back with a unique "
    "marker.\n"
    "Requests-only, benign, stay on the target host, full absolute urls."
)

_AUTH_SYS = (
    "You produce a login flow for a web app as JSON only:\n"
    '{"login": {"method":"POST","url":"https://.../login","headers":{"Content-Type":"application/json"},'
    '"body":"{...creds...}"}, "gated_probe": {"method":"GET","url":"https://.../<an endpoint that REQUIRES '
    'auth>"}, "authed_marker": "a short string present in the gated response ONLY when authenticated"}.\n'
    "Use the exact credentials given and the real login endpoint/shape from the recon (form vs JSON). The "
    "gated_probe must be an endpoint that returns the user's own data / a dashboard when logged in and "
    "401/403/redirect when not."
)


def _say(msg: str) -> None:
    sys.stderr.write("vera :: " + msg + "\n")
    sys.stderr.flush()


class _Store:
    def __init__(self, base_headers):
        self.hyps: list[dict] = []
        self.coverage: list[dict] = []
        self.traffic: list[dict] = []
        self.zap = None
        self.verify = True
        self.identities = {"anon": {"label": "anon", "headers": [], "cookies": {}, "alive": True}}
        if base_headers:
            self.identities["primary"] = {"label": "primary", "headers": list(base_headers),
                                          "cookies": {}, "alive": True}

    def identity(self, label):
        return self.identities.get(label or "anon", self.identities["anon"])

    def has_primary(self) -> bool:
        p = self.identities.get("primary")
        return bool(p and p.get("alive"))


# ---- HTTP send + predicate grading (the validation gate) --------------------------------------------------
def _as_header_dict(h) -> dict:
    out: dict[str, str] = {}
    if isinstance(h, dict):
        for k, v in h.items():
            out[str(k)] = str(v)
    elif isinstance(h, list):
        for item in h:
            if isinstance(item, dict):
                for k, v in item.items():
                    out[str(k)] = str(v)
            else:
                name, sep, val = str(item).partition(":")
                if sep:
                    out[name.strip()] = val.strip()
    return out


def _extract(resp) -> dict:
    try:
        body = resp.text or ""
    except Exception:  # noqa: BLE001
        body = ""
    return {"status": getattr(resp, "status_code", 0), "body": body,
            "headers": {k: v for k, v in getattr(resp, "headers", {}).items()}}


def _send_as(store: _Store, ident_label, req: dict, debug: bool) -> dict:
    ident = store.identity(ident_label)
    method = str(req.get("method") or "GET").upper()
    url = req.get("url") or ""
    headers: dict[str, str] = {}
    for h in ident.get("headers", []):
        name, _, val = str(h).partition(":")
        if val:
            headers[name.strip()] = val.strip()
    for name, val in _as_header_dict(req.get("headers")).items():
        headers[name] = val
    jar = ident.get("cookies") or {}
    if jar and not any(k.lower() == "cookie" for k in headers):
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
    t0 = time.monotonic()
    try:
        resp = http.request(method, url, headers=headers or None, data=req.get("body"), timeout=30,
                            verify=getattr(store, "verify", True))
        ex = _extract(resp)
        sc = resp.headers.get("set-cookie") if hasattr(resp, "headers") else None
        if sc:
            for part in str(sc).split(","):
                kv = part.split(";", 1)[0].strip()
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    jar[k.strip()] = v.strip()
            ident["cookies"] = jar
    except Exception as exc:  # noqa: BLE001
        ex = {"status": 0, "body": f"[request error: {exc}]", "headers": {}}
    ex["latency_ms"] = int((time.monotonic() - t0) * 1000)
    store.traffic.append({"identity": ident_label or "anon", "method": method, "url": url,
                          "status": ex["status"], "latency_ms": ex["latency_ms"]})
    return ex


def _check(pred: dict, primary: dict, control) -> tuple[bool, str]:
    ok, notes = True, []

    def note(k, good):
        notes.append(f"{k}={'ok' if good else 'FAIL'}")
        return good

    if "status_in" in pred:
        ok &= note("status_in", primary["status"] in pred["status_in"])
    if "latency_ms_gte" in pred:
        ok &= note("latency_ms_gte", primary.get("latency_ms", 0) >= pred["latency_ms_gte"])
    if "latency_ms_lt" in pred:
        ok &= note("latency_ms_lt", primary.get("latency_ms", 1 << 30) < pred["latency_ms_lt"])
    bc = pred.get("body_contains")
    if bc is not None:
        wants = [bc] if isinstance(bc, str) else list(bc)
        if wants:
            ok &= note("body_contains(any)", any(str(w) in primary["body"] for w in wants))
    bn = pred.get("body_not_contains")
    if bn is not None:
        for bad in ([bn] if isinstance(bn, str) else list(bn)):
            ok &= note(f"body_not_contains:{str(bad)[:20]}", str(bad) not in primary["body"])
    hc = pred.get("header_contains")
    if isinstance(hc, str) and hc:
        blob = " ".join(f"{k}: {v}" for k, v in primary["headers"].items()).lower()
        ok &= note(f"header_contains:{hc[:20]}", hc.lower() in blob)
    elif isinstance(hc, dict):
        # accept {headername: substr} AND the common model variant {"name": H, "substr": S}
        pairs = ([(hc.get("name"), hc.get("substr"))] if {"name", "substr"} <= set(hc)
                 else list(hc.items()))
        for name, sub in pairs:
            hv = next((v for k, v in primary["headers"].items() if k.lower() == str(name).lower()), "")
            ok &= note(f"header:{name}", str(sub).lower() in str(hv).lower())
    if pred.get("differs_from_control"):
        differs = control is not None and ((primary["status"] != control["status"])
                                           or (primary["body"] != control["body"]))
        ok &= note("differs_from_control", differs)
    if "control_status_in" in pred:
        ok &= note("control_status_in", control is not None and control["status"] in pred["control_status_in"])
    return ok, ", ".join(notes) or "no gradeable predicate keys"


# ---- recon + surface expansion ----------------------------------------------------------------------------
def _cap(raw: str, n: int = 6000) -> str:
    return raw if len(raw) <= n else raw[:n] + "\n...[truncated]"


def _call(argv: list, headers: list, debug: bool) -> str:
    from ..cli import main as cli_main
    try:
        flag = toolschema.build(argv[0])["flag_of"].get("header")
    except Exception:  # noqa: BLE001
        flag = None
    if flag and headers:
        argv = argv + [x for h in headers for x in (flag, h)]
    argv = agentlog.forward_debug(argv, debug)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            cli_main(list(argv))
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"success": False, "error": f"{argv[0]} failed: {exc}"})
    return buf.getvalue().strip()


def _openapi_endpoints(spec_url: str, headers: list, base: str, debug: bool) -> set:
    """Fetch an OpenAPI/Swagger spec and turn its paths into (METHOD, url) pairs the model can target."""
    eps = set()
    try:
        env = json.loads(_call(["http-request", spec_url], headers, debug))
        body = (env.get("data") or [{}])[0].get("content") or ""
        spec = json.loads(body)
        origin = base.rstrip("/")
        server = ""
        srvs = spec.get("servers") or []
        if srvs and isinstance(srvs[0], dict):
            server = str(srvs[0].get("url") or "").rstrip("/")
        for path, ops in (spec.get("paths") or {}).items():
            if not isinstance(ops, dict):
                continue
            full = path if path.startswith("http") else (server + path if server.startswith("http")
                                                         else origin + path)
            for method in ops:
                if str(method).lower() in ("get", "post", "put", "patch", "delete"):
                    eps.add((str(method).upper(), full))
    except Exception:  # noqa: BLE001
        pass
    return eps


def _recon(base: str, headers: list, debug: bool) -> tuple[str, list]:
    """Run the recon tools; return (text summary, sorted endpoint list [(METHOD,url)]) for the model to target."""
    parts, eps = [], set()
    for name, extra in _RECON:
        _say(f"recon: {name}")
        out = _call([name, base, *extra], headers, debug)
        parts.append(f"### {name}\n{_cap(out, 5000)}")
        try:
            data = json.loads(out).get("data") or []
        except Exception:  # noqa: BLE001
            data = []
        if name == "path-bust":
            for d in data:
                if isinstance(d, dict) and d.get("url"):
                    eps.add(("GET", d["url"]))
        elif name == "api-map":
            for d in data:
                if isinstance(d, dict) and d.get("url"):
                    for m in (d.get("methods") or d.get("verbs") or ["GET"]):
                        eps.add((str(m).upper(), d["url"]))
        elif name == "swagger-specs":
            for d in data:
                u = d.get("url") if isinstance(d, dict) else None
                if u:
                    eps |= _openapi_endpoints(u, headers, base, debug)
    endpoints = sorted(eps)[:250]
    if endpoints:
        _say(f"surface: {len(endpoints)} endpoint(s) mapped")
    return "\n\n".join(parts), endpoints


def _eps_text(endpoints: list) -> str:
    return "\n".join(f"{m} {u}" for m, u in endpoints) or "(none mapped)"


# ---- auth phase (login as a proven hypothesis) ------------------------------------------------------------
def _auth(provider, store: _Store, base: str, recon: str, endpoints: list, creds: str, dbg: bool) -> None:
    _say(f"===== AUTH: establishing identity for {creds.split(':',1)[0]} =====")
    user = (f"TARGET: {base}\nCREDENTIALS: {creds}\n\nRECON:\n{_cap(recon, 4000)}\n\n"
            f"ENDPOINTS:\n{_eps_text(endpoints)}\n\nProduce the login flow JSON.")
    try:
        obj = extract_json(provider.chat(_AUTH_SYS, user)) or {}
    except Exception as exc:  # noqa: BLE001
        _say(f"auth request failed: {exc}")
        return
    login, probe, marker = obj.get("login"), obj.get("gated_probe"), obj.get("authed_marker", "")
    if not isinstance(login, dict) or not login.get("url"):
        _say("auth: model produced no usable login request")
        return
    _say(f"AUTH login: {login.get('method','POST')} {login.get('url')}")
    store.identities["primary"] = {"label": "primary", "headers": [], "cookies": {}, "alive": False}
    _send_as(store, "primary", login, dbg)          # captures Set-Cookie/token into primary
    if isinstance(probe, dict) and probe.get("url"):
        p = _send_as(store, "primary", probe, dbg)
        a = _send_as(store, "anon", probe, dbg)
        alive = p["status"] == 200 and ((marker in p["body"]) if marker else (p["body"] != a["body"]))
        store.identities["primary"]["alive"] = alive
        _say(f"AUTH -> {'LOGGED IN' if alive else 'NOT CONFIRMED'} "
             f"(primary={p['status']} vs anon={a['status']} on {probe.get('url')})")
    else:
        store.identities["primary"]["alive"] = True
        _say("AUTH -> login sent (no gated probe to confirm; treating as alive)")


# ---- the phased pipeline ----------------------------------------------------------------------------------
def _request_hypotheses(provider, base, recon, endpoints, tried, prior_note, has_primary, dbg) -> list[dict]:
    ident_note = ("An AUTHENTICATED identity 'primary' is available - use as_identity='primary' with "
                  "control_identity='anon' for authz/IDOR tests.\n" if has_primary else
                  "No authenticated identity (test unauth surface + anything reachable as anon).\n")
    user = (f"TARGET: {base}\nSCOPE: {urlparse(base).hostname}\n{ident_note}\n"
            f"KNOWN vuln classes: {', '.join(n for n, _ in skills.catalog())}\n\n"
            f"RECON:\n{recon}\n\nENDPOINTS (test these for IDOR/authz/injection):\n{_eps_text(endpoints)}\n\n"
            f"{prior_note}Output JSON only: `plan` + `hypotheses`.")
    try:
        raw = provider.chat(_HYP_SYS, user)
    except Exception as exc:  # noqa: BLE001
        _say(f"hypothesis request failed: {exc}")
        return []
    obj = extract_json(raw) or {}
    plan = obj.get("plan") or []
    if plan:
        _say(f"PLAN ({len(plan)} steps):")
        for s in plan:
            _say("   - " + str(s)[:140])
    hyps = []
    for h in obj.get("hypotheses") or []:
        if not isinstance(h, dict) or not h.get("claim"):
            continue
        req = h.get("test_request") or {}
        key = f"{h.get('vuln_class','')}|{(req.get('method') or 'GET')}|{req.get('url','')}".lower()
        if key in tried:
            continue
        tried.add(key)
        h.setdefault("evidence", [])
        hyps.append(h)
        _say(f"HYPOTHESIS [{h.get('vuln_class','?')}] {h.get('claim','')[:120]}")
        if h.get("rationale"):
            _say(f"   WHY: {str(h['rationale'])[:200]}")
        if h.get("impact"):
            _say(f"   IMPACT: {str(h['impact'])[:200]}")
        _say(f"   PREDICT: {json.dumps(h.get('predicted_observable') or {})[:180]}"
             + (f"  TOOL: {h.get('tool')}" if h.get("tool") else "")
             + (f"  AS: {h.get('as_identity')}" if h.get("as_identity") else ""))
    if not hyps:
        _say("no NEW hypotheses this round")
    return hyps


def _validate_tool(store: _Store, h: dict, headers: list, dbg: bool) -> bool:
    """Prove an injection/extraction hypothesis by running the real boxcutter tool (fuzz/sqlmap self-confirm).
    Returns True if it handled the hypothesis. A tool hit is genuine exploitation, so it bypasses the impact
    gate; no hit -> open_proof_gap."""
    tool = str(h.get("tool") or "").lower()
    req = h.get("test_request") or {}
    url = req.get("url")
    if tool not in ("fuzz", "sqlmap") or not url:
        return False
    argv = [tool, url]
    if h.get("tool_args"):
        import shlex
        argv += shlex.split(str(h["tool_args"]))
    _say(f"   TOOL: {tool} {url}")
    out = _call(argv, headers, dbg)
    try:
        data = json.loads(out).get("data") or []
    except Exception:  # noqa: BLE001
        data = []
    found = bool(data)
    h["status"] = "confirmed" if found else "open_proof_gap"
    h["tier"] = f"tool:{tool}"
    h["evidence"].append({"tool": tool, "url": url, "findings": len(data),
                          "sample": json.dumps(data[:2])[:300]})
    store.coverage.append({"surface": url, "verdict": h["status"]})
    _say(f"VALIDATE [{h.get('vuln_class','?')}] -> {h['status'].upper()} (tool:{tool}) findings={len(data)}")
    return True


def _validate_one(store: _Store, h: dict, headers: list, dbg: bool) -> None:
    if h.get("tool") and _validate_tool(store, h, headers, dbg):
        return
    pred = h.get("predicted_observable") or {}
    req = h.get("test_request") or {}
    if not req.get("url"):
        h["status"], h["tier"] = "open_proof_gap", "model-judged"
        _say(f"VALIDATE [{h.get('vuln_class','?')}] -> OPEN_PROOF_GAP (no test_request url)")
        return
    as_id = h.get("as_identity") or "anon"
    if as_id == "primary" and not store.has_primary():
        as_id = "anon"
    ctl_id = h.get("control_identity") or "anon"
    primary = _send_as(store, as_id, req, dbg)
    control = None
    if pred.get("differs_from_control") or "control_status_in" in pred:
        control = _send_as(store, ctl_id, h.get("control_request") or req, dbg)
    try:
        passed, detail = _check(pred, primary, control)
    except Exception as exc:  # noqa: BLE001
        passed, detail = False, f"predicate error: {exc}"
    refuted = False
    if not passed and h.get("refute_if"):
        try:
            refuted, _ = _check(h["refute_if"], primary, control)
        except Exception:  # noqa: BLE001
            refuted = False
    h["status"] = "confirmed" if passed else ("ruled_out" if refuted else "open_proof_gap")
    # A status-only predicate on a state-changing method proves the request was ACCEPTED, not that the effect
    # happened (a 200 to PUT is not a proven upload). Downgrade to a proof gap - a write needs proof-of-effect.
    if (h["status"] == "confirmed" and str(req.get("method") or "GET").upper() not in ("GET", "HEAD")
            and set(pred) <= {"status_in"}):
        h["status"] = "open_proof_gap"
        detail += " | downgraded: status-only proof on a write method is not effect-proof"
    # Impact gate: a confirmation that only re-observes the page (no sensitive content, no differential, no
    # timing) is an OBSERVATION, not a finding - downgrade it. This is what stops '/admin returns 200 with its
    # own title' from being reported as a vuln.
    if h["status"] == "confirmed" and not _impactful(pred, primary, control):
        h["status"] = "open_proof_gap"
        detail += " | downgraded: observation only, no proven impact (needs sensitive content, a differential, or timing)"
    h["tier"] = "machine-checked" if (set(pred) & _PRED_KEYS) else "model-judged"
    h["evidence"].append({"request": {"method": req.get("method", "GET"), "url": req.get("url"),
                                      "as": as_id}, "primary_status": primary["status"],
                          "latency_ms": primary["latency_ms"],
                          "control_status": control["status"] if control else None, "detail": detail})
    store.coverage.append({"surface": req.get("url"), "verdict": h["status"]})
    _say(f"VALIDATE [{h.get('vuln_class','?')}] -> {h['status'].upper()} ({h['tier']}) "
         f"as={as_id} primary={primary['status']} control={control['status'] if control else '-'} :: {detail}")


# ---- report -----------------------------------------------------------------------------------------------
def _findings(store: _Store) -> list[dict]:
    out = []
    for h in store.hyps:
        if h.get("status") not in ("confirmed", "open_proof_gap"):
            continue
        sev = (h.get("severity") or ("high" if h["status"] == "confirmed" else "medium")).lower()
        tag = "CONFIRMED" if h["status"] == "confirmed" else "UNPROVEN (open proof gap)"
        out.append({"severity": sev, "title": f"{h.get('claim','')} [{tag}]",
                    "info": f"class={h.get('vuln_class','')} tier={h.get('tier')}. {h.get('rationale','')} "
                            f"evidence={json.dumps(h.get('evidence') or [])[:600]}", "url": ""})
    return out


def _report(store: _Store) -> str:
    conf = [h for h in store.hyps if h.get("status") == "confirmed"]
    gaps = [h for h in store.hyps if h.get("status") == "open_proof_gap"]
    ruled = [h for h in store.hyps if h.get("status") == "ruled_out"]
    L = ["# vera report", "",
         f"Confirmed: {len(conf)} | Open proof gaps: {len(gaps)} | Ruled out: {len(ruled)} | "
         f"Requests: {len(store.traffic)}", ""]
    if conf:
        L += ["## Confirmed findings", ""]
        for h in conf:
            L += [f"### [{(h.get('severity') or 'high').upper()}] {h.get('claim','')}",
                  f"- class: {h.get('vuln_class','')} | tier: {h.get('tier')}",
                  f"- why: {h.get('rationale','')}",
                  f"- evidence: `{json.dumps(h.get('evidence') or [])[:400]}`", ""]
    if gaps:
        L += ["## Open proof gaps (plausible, not proven)", ""]
        L += [f"- [{h.get('vuln_class','')}] {h.get('claim','')}" for h in gaps] + [""]
    if ruled:
        L += ["## Ruled out (secure behaviour)", ""]
        L += [f"- {h.get('claim','')}" for h in ruled] + [""]
    return "\n".join(L)


def _confirmed_summary(store: _Store) -> str:
    conf = [h for h in store.hyps if h.get("status") == "confirmed"]
    if not conf:
        return "none yet"
    return "; ".join(f"[{h.get('vuln_class','')}] {h.get('claim','')[:70]}" for h in conf[-12:])


def add_arguments(parser) -> None:
    parser.add_argument("target", nargs="?",
                        help="Target URL (or a comma-separated list). Omit when using --targets-file.")
    parser.add_argument("--targets", dest="targets", default=None, metavar="URL,URL",
                        help="Comma-separated targets to orchestrate over (each gets its own isolated run).")
    parser.add_argument("--targets-file", dest="targets_file", default=None, metavar="PATH",
                        help="Read one target URL/host per line from PATH (# comments and blanks ignored) and "
                             "sweep them all, one isolated phased run each. This is vera's orchestrator mode.")
    parser.add_argument("--out-dir", dest="out_dir", default=None, metavar="DIR",
                        help="In multi-target mode, write a per-target report <slug>.md + an INDEX.md here.")
    parser.add_argument("--max-rounds", dest="max_rounds", type=int, default=8,
                        help="Max deepen rounds (default 8). Each round chains off the prior confirmed findings "
                             "+ endpoint surface; stops early when a round finds nothing new.")
    parser.add_argument("--creds", dest="creds", default=None, metavar="USER:PASS",
                        help="Credentials for the auth phase (login as a proven hypothesis) so authenticated "
                             "classes - IDOR/BOLA, function-level authz, business logic - become reachable.")
    parser.add_argument("--zap", action="store_true",
                        help="Capture ALL traffic through the bundled ZAP proxy daemon (needs zap.sh).")
    add_agent_args(parser, max_steps=0)


def _collect_targets(args) -> list[str]:
    """Build the target list from the positional arg (may be comma-separated), --targets, and --targets-file.
    Normalizes to URLs, drops blanks / # comments, de-dupes preserving order. This is what makes vera an
    orchestrator: 1 target or thousands, each scanned in isolation."""
    raw: list[str] = []
    if getattr(args, "target", None):
        raw += args.target.split(",")
    if getattr(args, "targets", None):
        raw += args.targets.split(",")
    if getattr(args, "targets_file", None):
        try:
            with open(args.targets_file, encoding="utf-8") as fh:
                raw += fh.read().splitlines()
        except OSError as exc:
            sys.stderr.write(f"vera: cannot read --targets-file: {exc}\n")
    out: list[str] = []
    for t in (x.strip() for x in raw):
        if not t or t.startswith("#"):
            continue
        u = t if t.startswith(("http://", "https://")) else "https://" + t
        if u not in out:
            out.append(u)
    return out


def _slug(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", (urlparse(url).hostname or url)).strip("-") or "target"


def _scan_one(provider, target: str, headers: list, args, verify) -> _Store:
    """Run the full phased+deepening pipeline against ONE target, isolated in its own store/session."""
    store = _Store(headers)
    store.verify = verify
    _say(f"===== TARGET {target} =====")
    recon, endpoints = _recon(target, headers, args.debug)
    if args.creds:
        _auth(provider, store, target, recon, endpoints, args.creds, args.debug)
    tried: set = set()
    prior_note = ""
    for rnd in range(1, max(1, args.max_rounds) + 1):
        _say(f"===== {_slug(target)} ROUND {rnd}/{args.max_rounds} =====")
        hyps = _request_hypotheses(provider, target, recon, endpoints, tried, prior_note,
                                   store.has_primary(), args.debug)
        if not hyps:
            _say("no new hypotheses - stopping early")
            break
        store.hyps.extend(hyps)
        for h in hyps:
            _validate_one(store, h, headers, args.debug)
        prior_note = (f"CONFIRMED SO FAR: {_confirmed_summary(store)}.\n"
                      f"Propose ONLY NEW hypotheses (different endpoint/class than already tested); go DEEPER - "
                      f"chain from confirmed findings, and test the mapped endpoints for IDOR/authz/injection "
                      f"{'as the primary identity' if store.has_primary() else ''}.\n\n")
    return store


def run(args) -> int:
    targets = _collect_targets(args)
    if not targets:
        output_result([], args.output, "no target: pass a URL, --targets, or --targets-file")
        return 1
    provider_cls = PROVIDERS[args.provider]
    key = getattr(args, "api_key", None) or os.environ.get(provider_cls.env)
    if not key and getattr(provider_cls, "requires_key", True):
        sys.stderr.write(f"vera: an LLM is required - provide --api-key or set {provider_cls.env}\n")
        return 2
    provider = make_provider(args.provider, args.model, key, base_url=getattr(args, "base_url", None),
                             reasoning=getattr(args, "reasoning", 0))
    headers = list(getattr(args, "header", None) or [])

    # ZAP proxy is process-global (env), so start it ONCE and every target's traffic flows through it.
    zap, verify = None, True
    if getattr(args, "zap", False):
        zap = _zapproxy.start(_say)
        if zap:
            for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                os.environ[var] = zap.proxy
            if zap.ca_file:
                os.environ["REQUESTS_CA_BUNDLE"] = zap.ca_file
                os.environ["SSL_CERT_FILE"] = zap.ca_file
            verify = zap.ca_file or False

    _say(f"orchestrator: {len(targets)} target(s) provider={args.provider}"
         f"{' model=' + args.model if args.model else ''} rounds={args.max_rounds}"
         f"{' +creds' if args.creds else ''}")
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)

    all_findings: list[dict] = []
    rows: list[tuple] = []
    try:
        for i, target in enumerate(targets, 1):
            if not is_valid_url(target):
                _say(f"[{i}/{len(targets)}] skip invalid target: {target}")
                continue
            store = _scan_one(provider, target, headers, args, verify)
            fs = _findings(store)
            for x in fs:
                x["url"] = target                       # tag each finding with its target
            all_findings += fs
            conf = sum(1 for h in store.hyps if h.get("status") == "confirmed")
            gaps = sum(1 for h in store.hyps if h.get("status") == "open_proof_gap")
            rows.append((target, conf, gaps))
            _say(f"[{i}/{len(targets)}] {target} -> {conf} confirmed, {gaps} proof-gaps")
            if args.out_dir:
                try:
                    with open(os.path.join(args.out_dir, f"{_slug(target)}.md"), "w", encoding="utf-8") as fh:
                        fh.write(f"# {target}\n\n" + _report(store) + "\n")
                except OSError as exc:
                    _say(f"could not write per-target report: {exc}")
    finally:
        if zap:
            _zapproxy.shutdown(zap)

    # aggregate index across targets
    index = ["# vera orchestrator - findings index", "",
             f"{len(rows)} target(s) scanned.", "",
             "| Target | Confirmed | Proof gaps |", "|---|--:|--:|"]
    for t, c, g in sorted(rows, key=lambda r: (-r[1], r[0])):
        index.append(f"| {t} | {c} | {g} |")
    index_md = "\n".join(index)
    if args.out_dir:
        try:
            with open(os.path.join(args.out_dir, "INDEX.md"), "w", encoding="utf-8") as fh:
                fh.write(index_md + "\n")
        except OSError:
            pass
    if getattr(args, "report", None):
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(index_md + "\n")
        except OSError as exc:
            sys.stderr.write(f"vera: could not write report: {exc}\n")
    _say("\n" + index_md)
    output_result(all_findings, args.output)
    return 0

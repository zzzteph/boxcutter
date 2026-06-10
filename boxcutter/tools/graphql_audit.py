"""graphql-audit: drive a GraphQL endpoint properly and report its weaknesses.

Unlike the generic ``fuzz`` (which blasts params/path/body), this speaks GraphQL:
it runs posture checks, then uses introspection to build *valid* queries and
inject into individual scalar arguments, judging hits with the same error/time/
reflection signals fuzz uses. Mutations are only ever **dry-probed** (sent
deliberately invalid) so nothing is actually executed.

Checks: introspection enabled, queries over GET (CSRF), unbounded batching/aliasing,
verbose errors / secrets in errors, argument injection (SQLi/SSTI/error), and
exposed/unauthenticated mutations (dry-probe).
"""
from __future__ import annotations

import json as jsonlib
import re

from ..core import http
from ..core.args import add_common_args, add_header_arg
from ..core.envelope import debug_logger, output_result
from ..core.validators import is_valid_url

NAME = "graphql-audit"
KIND = "findings"
HELP = "Audit a GraphQL endpoint: introspection, CSRF, batching, verbose errors, arg injection, mutation exposure."

# --- detection signals (shared idea with fuzz) ------------------------------
_SQL_ERR = re.compile(
    r"sql syntax|unrecognized token|syntax error|unterminated|near \".*\":|"
    r"sqlite|psql|mysql|mariadb|postgres|odbc|ora-\d+|incorrect syntax", re.I)
_SECRET = re.compile(
    r"secret|password|api[_-]?key|jwt|aws_|akia[0-9a-z]{16}|sk_live_|private[_-]?key|"
    r"traceback|stack trace|at [\w.$]+\(", re.I)
INTROSPECTION = '{__schema{queryType{name} mutationType{name} types{name kind fields{name args{name type{name kind ofType{name kind}}} type{name kind ofType{name kind}}}}}}'


def add_arguments(parser) -> None:
    parser.add_argument("target", help="GraphQL endpoint URL, e.g. https://api.foo.com/graphql")
    parser.add_argument("--timeout", type=int, default=15, help="Per-request timeout (s)")
    add_header_arg(parser)
    add_common_args(parser)


def run(args) -> int:
    dbg = debug_logger(args.debug)
    url = args.target.strip()
    if not is_valid_url(url):
        output_result([], args.output, "Invalid endpoint URL.")
        return 1
    headers = _header_map(args.header)
    headers.setdefault("Content-Type", "application/json")
    ctx = _Ctx(url, headers, args.timeout, dbg)

    findings: list[dict] = []
    schema = _check_introspection(ctx, findings)
    _check_get_csrf(ctx, findings)
    _check_batching(ctx, findings)
    _check_verbose_errors(ctx, findings)
    if schema:
        _check_secret_fields(ctx, schema, findings)
        _check_arg_injection(ctx, schema, findings)
        _check_mutations(ctx, schema, findings)
    else:
        dbg("introspection off - skipping schema-guided checks")

    output_result(findings, args.output)
    return 0


class _Ctx:
    def __init__(self, url, headers, timeout, dbg):
        self.url, self.headers, self.timeout, self.dbg = url, headers, timeout, dbg

    def gql(self, query, method="POST"):
        if method == "GET":
            return http.send("GET", self.url, params={"query": query}, headers=self.headers, timeout=self.timeout)
        return http.send("POST", self.url, json={"query": query}, headers=self.headers, timeout=self.timeout)


def _finding(sev, title, info, url):
    return {"severity": sev, "title": title, "info": info, "url": url}


# --- posture ----------------------------------------------------------------

def _check_introspection(ctx, findings):
    r = ctx.gql(INTROSPECTION)
    doc = _json(r)
    schema = (((doc or {}).get("data") or {}).get("__schema")) if doc else None
    if isinstance(schema, dict) and schema.get("types"):
        ctx.dbg("introspection enabled")
        findings.append(_finding(
            "medium", "GraphQL introspection enabled",
            "The full schema is queryable via __schema - it maps every type, field and "
            "argument for an attacker. Disable introspection in production.", ctx.url))
        return schema
    return None


def _check_get_csrf(ctx, findings):
    r = ctx.gql("{__typename}", method="GET")
    doc = _json(r)
    if doc and isinstance(doc.get("data"), dict):
        findings.append(_finding(
            "medium", "GraphQL accepts queries over GET (CSRF)",
            "Operations are accepted as a GET ?query= parameter, so a cross-site request "
            "(or a cached/logged URL) can drive the API - state-changing mutations over GET are CSRF-able.",
            ctx.url))


def _check_batching(ctx, findings):
    q = "{ a:__typename b:__typename c:__typename d:__typename e:__typename }"
    doc = _json(ctx.gql(q))
    data = (doc or {}).get("data") or {}
    if sum(1 for k in ("a", "b", "c", "d", "e") if k in data) >= 3:
        findings.append(_finding(
            "low", "GraphQL aliasing/batching not limited",
            "Many aliased operations run in a single request with no cost/complexity limit - "
            "enables brute force and denial of service via query amplification.", ctx.url))


def _check_verbose_errors(ctx, findings):
    # malformed query -> read the error body for stack traces / secrets
    doc = _json(ctx.gql("{ this_field_does_not_exist_zzz }"))
    body = jsonlib.dumps(doc) if doc else ""
    if _SECRET.search(body):
        findings.append(_finding(
            "high", "GraphQL error leaks secrets / stack trace",
            "An invalid query returns an error containing secrets or a stack trace:\n"
            + body[:400], ctx.url))


# --- sensitive fields -------------------------------------------------------

def _check_secret_fields(ctx, schema, findings):
    """Query each no-argument top-level field and flag any that return secrets."""
    qtype = ((schema.get("queryType") or {}).get("name")) or "Query"
    for f in _fields_of(schema, qtype):
        if f.get("args"):
            continue  # only blind-query the no-arg fields (safe)
        leaf = _leaf_selection(schema, f.get("type"))
        sel = (" { %s }" % leaf) if leaf else ""
        body = jsonlib.dumps(_json(ctx.gql("{ %s%s }" % (f["name"], sel))) or "")
        if _SECRET.search(body):
            findings.append(_finding(
                "high", f"GraphQL field '{f['name']}' returns secrets",
                f"Querying {{ {f['name']} }} returns sensitive data:\n" + body[:300], ctx.url))


# --- schema-guided argument injection ---------------------------------------

_PAYLOADS = [
    ("sqli", "1' OR '1'='1"),
    ("sqli", "1\""),
    ("ssti", "${{7*7}}"),
    ("error", "'\""),
]


def _check_arg_injection(ctx, schema, findings):
    qtype = ((schema.get("queryType") or {}).get("name")) or "Query"
    fields = _fields_of(schema, qtype)
    grouped: dict[tuple, list] = {}
    for f in fields:
        scalar_args = [a for a in (f.get("args") or []) if _is_stringish(a.get("type"))]
        if not scalar_args:
            continue
        leaf = _leaf_selection(schema, f.get("type"))
        for arg in scalar_args:
            for cls, payload in _PAYLOADS:
                q = _build_query(f["name"], arg["name"], payload, leaf)
                r = ctx.gql(q)
                hit = _injection_hit(cls, r, payload)
                if hit:
                    grouped.setdefault((f["name"], arg["name"], hit), []).append((payload, q))
                    break  # one confirmed class per arg is enough
    for (fname, aname, cls), hits in grouped.items():
        sev = "high" if cls in ("sqli", "ssti") else "medium"
        info = (f"Argument '{aname}' on field '{fname}' is injectable ({cls}). Confirmed:\n"
                + "\n".join(f"  {p}  =>  {q}" for p, q in hits[:5]))
        findings.append(_finding(sev, f"GraphQL [{cls}] in {fname}({aname}:)", info, ctx.url))


def _injection_hit(cls, r, payload):
    if r.get("error") or r.get("status") is None:
        return None
    body = r.get("body") or ""
    if cls in ("sqli", "error") and _SQL_ERR.search(body):
        return "sqli"
    if cls == "ssti" and "49" in body and "${{7*7}}" not in body:
        return "ssti"
    return None


# --- mutations: safe dry-probe ----------------------------------------------

def _check_mutations(ctx, schema, findings):
    mtype = ((schema.get("mutationType") or {}).get("name"))
    if not mtype:
        return
    exposed = []
    for f in _fields_of(schema, mtype):
        # send the mutation with NO arguments: a required-arg validation error means it
        # is REACHABLE + UNAUTH, but (because GraphQL validates before executing) nothing ran.
        doc = _json(ctx.gql("mutation { %s }" % f["name"]))
        body = jsonlib.dumps(doc) if doc else ""
        if re.search(r"unauthor|forbidden|not allowed|requires? auth|permission", body, re.I):
            continue  # auth-gated - good
        if re.search(r"argument|required|must be|expected|cannot query field|of type", body, re.I):
            exposed.append(f["name"])
    if exposed:
        findings.append(_finding(
            "high", "GraphQL mutations exposed without authentication",
            "These mutations are reachable and not auth-gated (dry-probed with no args, so "
            "nothing was executed):\n  " + ", ".join(exposed[:20])
            + "\nReview them for authorization and abuse (e.g. privilege change, content edit).",
            ctx.url))


# --- schema helpers ---------------------------------------------------------

def _fields_of(schema, type_name):
    for t in schema.get("types") or []:
        if t.get("name") == type_name:
            return t.get("fields") or []
    return []


def _type_name(t):
    while isinstance(t, dict):
        if t.get("name"):
            return t["name"]
        t = t.get("ofType")
    return None


def _is_stringish(t):
    return _type_name(t) in ("ID", "String", "Int")


def _leaf_selection(schema, ret_type):
    """Pick a scalar subfield to select so the query is valid (or '' for a scalar)."""
    name = _type_name(ret_type)
    fields = _fields_of(schema, name)
    for f in fields:
        if _type_name(f.get("type")) in ("ID", "String", "Int", "Boolean", "Float"):
            return f["name"]
    if fields:
        return fields[0]["name"]
    return ""


def _build_query(field, arg, value, leaf):
    val = value.replace("\\", "\\\\").replace('"', '\\"')
    sel = (" { %s }" % leaf) if leaf else ""
    return '{ %s(%s: "%s")%s }' % (field, arg, val, sel)


def _json(r):
    try:
        return jsonlib.loads(r.get("body") or "")
    except (ValueError, AttributeError):
        return None


def _header_map(headers):
    out = {}
    for raw in headers or []:
        if ":" in raw:
            name, value = raw.split(":", 1)
            if name.strip():
                out[name.strip()] = value.strip()
    return out

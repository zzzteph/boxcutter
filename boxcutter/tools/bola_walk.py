"""bola-walk - two-session cross-account authorization diff (BOLA / IDOR), in one command.

BOLA/IDOR testing is a tedious manual chore in Burp: grab an object id as user A, replay it as user B, diff. bola-walk
does it end-to-end. Give it a URL with an object id and TWO authenticated sessions; it walks the id space and reports
where identity B can read an object that is genuinely ACCESS-CONTROLLED. The 3-way test kills false positives: an id
counts as BOLA only when the UNAUTHENTICATED request is gated (401/403/404) AND identity B gets a 200 with real data
on an object that is not B's own - i.e. B read someone else's record.

Non-destructive: GET only (unless --method given for a write-BOLA check). Point it at any id-bearing endpoint:
  bola-walk https://api.tld/v1/orders/1042 -A "Authorization: Bearer <A>" -B "Authorization: Bearer <B>" --range 1000-1050
  bola-walk "https://api.tld/account?id=7" -A "Cookie: s=<A>" -B "Cookie: s=<B>"
"""
from __future__ import annotations

import concurrent.futures as cf
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result

NAME = "bola-walk"
KIND = "findings"
HELP = ("Two-session cross-account authorization diff (BOLA/IDOR): walk an object id and report where identity B "
        "reads an access-controlled object that isn't B's. 3-way (unauth/A/B) test, non-destructive.")


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL with an object id, e.g. https://x/api/orders/1042 or https://x/a?id=7")
    parser.add_argument("-A", "--session-a", action="append", default=[], metavar="HDR",
                        help="header(s) for identity A (the owner), repeatable, 'Name: value'")
    parser.add_argument("-B", "--session-b", action="append", default=[], metavar="HDR",
                        help="header(s) for identity B (the attacker), repeatable")
    parser.add_argument("--range", dest="idrange", default=None,
                        help="id range/list to walk: '1000-1050' or '1,2,3' (default: the URL's id +/- 10)")
    parser.add_argument("--concurrency", type=int, default=8, help="parallel id probes (default 8)")
    add_common_args(parser)


def _hmap(hdrs):
    d = {}
    for h in (hdrs or []):
        if ":" in h:
            k, v = h.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def _locate_id(target):
    """Return (kind, template, current_id): kind='path' or 'query'. template has {ID} where the id goes."""
    pr = urlparse(target)
    q = dict(parse_qsl(pr.query, keep_blank_values=True))
    for k in ("id", "user_id", "uid", "account", "order", "oid", "pid", "num"):     # numeric query param
        if k in q and q[k].isdigit():
            cur = int(q[k]); q2 = dict(q); q2[k] = "{ID}"
            return "query", urlunparse(pr._replace(query=urlencode(q2).replace("%7BID%7D", "{ID}"))), cur
    segs = pr.path.split("/")                                                        # numeric path segment
    for i in range(len(segs) - 1, -1, -1):
        if segs[i].isdigit():
            cur = int(segs[i]); segs2 = list(segs); segs2[i] = "{ID}"
            return "path", urlunparse(pr._replace(path="/".join(segs2))), cur
    return None, target, None


def _ids(spec, cur):
    if spec:
        out = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                if a.isdigit() and b.isdigit():
                    out += list(range(int(a), int(b) + 1))
            elif part.isdigit():
                out.append(int(part))
        return out[:200]
    if cur is None:
        return []
    return [i for i in range(max(1, cur - 10), cur + 11)]


def run(args) -> int:
    dbg = debug_logger(args.debug)
    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    if not args.session_b:
        output_result([], args.output, "Need identity B (-B). Give two sessions to diff (A owner, B attacker).")
        return 1
    kind, template, cur = _locate_id(target)
    if kind is None:
        output_result([], args.output, "No object id found in the URL (need a numeric path segment or ?id=).")
        return 1
    ids = _ids(args.idrange, cur)
    sess_none = http.session()
    sess_a = http.session(extra_headers=_hmap(args.session_a)) if args.session_a else None
    sess_b = http.session(extra_headers=_hmap(args.session_b))
    dbg(f"bola-walk: {kind} id, walking {len(ids)} ids on {template}")

    def probe(i):
        url = template.replace("{ID}", str(i))
        rn = http.send("GET", url, sess=sess_none, timeout=10, allow_redirects=False)
        rb = http.send("GET", url, sess=sess_b, timeout=10, allow_redirects=False)
        ra = http.send("GET", url, sess=sess_a, timeout=10, allow_redirects=False) if sess_a else {"status": None}
        return i, url, rn, ra, rb

    findings = []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        for i, url, rn, ra, rb in ex.map(probe, ids):
            ns, bs = rn.get("status"), rb.get("status")
            blen = rb.get("body_bytes", 0)
            # BOLA: unauth is GATED, but identity B reads it with real content
            if ns in (401, 403, 404) and bs in (200, 201) and blen > 64:
                owner = (ra.get("status") in (200, 201)) if sess_a else None
                findings.append({"severity": "high", "title": f"BOLA/IDOR: identity B reads {urlparse(url).path}",
                                 "url": url,
                                 "info": f"unauth={ns} (gated) but B={bs} ({blen}b) — B accessed an access-controlled "
                                         f"object" + (f"; A={ra.get('status')} (owner) confirms it's a real record" if owner else "")})
    dbg(f"bola-walk: {len(findings)} cross-account access(es)")
    output_result(findings, args.output)
    return 0

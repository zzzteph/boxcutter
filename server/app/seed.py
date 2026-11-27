"""First-boot / every-boot seed: the admin password, the built-in template catalog, the distributed versions of
the composite workflows, notification settings and an optional enroll token.

Built-in templates are read-only in the UI and re-synced from this file on every start (matched by name), so
an upgrade ships new descriptions/stages automatically. Custom templates are never touched.

Catalog fields (all user-facing):
  title     - plain-language name shown on the scan-type cards
  category  - grouping in the picker
  accepts   - what a target must look like: domain | host (domain, hostname, IP or URL) | url | endpoint
              (URL with parameters) | js (JS file URL) | spec (OpenAPI URL or host) | graphql | network
  produces  - findings | hosts | urls | items - what it hands to a next pipeline step
  depth     - quick | standard | deep (rough cost)
"""
from __future__ import annotations

import json

from sqlmodel import Session, select

from .config import settings
from .db import engine
from .models import EnrollToken, NotifySettings, Scheduler, Template
from .pipeline import DEFAULT_INPUT, SEED
from .security import ensure_admin, hash_token

# name: (kind, title, category, accepts, produces, depth, description)
CATALOG: dict[str, tuple] = {
    # ---- workflows (engine YAML recipes; one job per target) ------------------------------------------------
    "web-full": ("workflow", "Full website scan", "Websites", "host", "findings", "deep",
                 "Checks the site is up, then runs nuclei template passes and the deep scan (crawl, fuzzing, "
                 "sqlmap, OpenAPI, GraphQL, JS secrets) on every live URL. The default choice for a website."),
    "web-scan": ("workflow", "Deep scan of a URL", "Websites", "url", "findings", "deep",
                 "Crawls the URL, then fuzz + nuclei DAST + sqlmap on every parameter, fuzzes captured POST "
                 "bodies, tests OpenAPI and GraphQL endpoints and scans JS files for secrets."),
    "web-nuclei": ("workflow", "Known vulnerabilities (nuclei)", "Websites", "url", "findings", "quick",
                   "Nuclei template passes: exposures, misconfigurations, recent CVEs, known-exploited (KEV) "
                   "and exposed admin panels. Fast, low noise."),
    "spa-scan": ("workflow", "Single-page app scan", "Websites", "url", "findings", "deep",
                 "For JavaScript apps: a real-browser crawl (clicks, forms, the cross-origin API), then every "
                 "captured endpoint and request body is tested, plus GraphQL and JS secrets."),
    "web-fuzz": ("workflow", "Website scan — fuzzer only", "Websites", "url", "findings", "standard",
                 "Like the deep scan, but injection testing is done by the built-in fuzzer only (no sqlmap)."),
    "web-sqlmap": ("workflow", "Website scan — sqlmap only", "Websites", "url", "findings", "deep",
                   "Like the deep scan, but injection testing is done by sqlmap only (no fuzzer)."),
    "endpoint-scan": ("workflow", "Scan one endpoint", "Websites", "endpoint", "findings", "standard",
                      "One URL with parameters: fuzzer + nuclei DAST, and sqlmap only when the fuzzer sees SQL "
                      "injection (double-confirmed)."),
    "web-crawl": ("workflow", "Crawl a website", "Discovery", "url", "items", "standard",
                  "Katana spider plus a real-browser crawl (SPA-aware): every URL and request the site uses."),
    "recon": ("workflow", "Find subdomains", "Discovery", "domain", "hosts", "quick",
              "Subdomains from passive sources (subfinder, web archives) and a DNS brute-force, kept only if "
              "they resolve."),
    "recon-http": ("workflow", "Find live websites of a domain", "Discovery", "domain", "urls", "quick",
                   "Subdomain discovery, then httpx: the live HTTP(S) services of a domain, one URL each."),
    "ip-discover": ("workflow", "Find live hosts in a network", "Network", "network", "hosts", "quick",
                    "Ping sweep (nmap -sn) of an IP, CIDR or range: the hosts that answer."),
    "env-scan": ("workflow", "Whole environment scan", "Environment", "domain", "findings", "deep",
                 "Every subdomain of a domain gets the full website scan and the web-archive scan. The most "
                 "thorough (and slowest) option."),
    "env-nuclei": ("workflow", "Nuclei on all subdomains", "Environment", "domain", "findings", "standard",
                   "Finds subdomains, keeps the live web services and runs the nuclei template passes on each."),
    "env-takeover": ("workflow", "Subdomain takeover check", "Environment", "domain", "findings", "quick",
                     "Finds subdomains and runs nuclei's takeover templates on every one of them."),
    "env-secrets": ("workflow", "Secrets on all subdomains", "Environment", "domain", "findings", "standard",
                    "Crawls every live subdomain and scans the JavaScript it loads for keys and tokens."),
    "env-wayback": ("workflow", "Archived URLs of all subdomains", "Environment", "domain", "findings",
                    "standard", "Web-archive URLs of every subdomain; each parameterised URL is scanned "
                    "(fuzzer + nuclei DAST + sqlmap if SQLi)."),
    "env-wayback-secrets": ("workflow", "Archived JS secrets of all subdomains", "Environment", "domain",
                            "findings", "standard",
                            "For every subdomain: JS files from a crawl and the web archives, scanned for "
                            "secrets."),
    "swagger-scan": ("workflow", "OpenAPI / Swagger scan", "APIs", "spec", "findings", "standard",
                     "Finds the OpenAPI spec(s) on a host (or give the spec URL) and tests every documented "
                     "endpoint: fuzzer + nuclei DAST, sqlmap when SQLi is suspected."),
    "swagger-fuzz": ("workflow", "OpenAPI fuzzing", "APIs", "spec", "findings", "standard",
                     "Finds the OpenAPI spec(s) and fuzzes every parameterised endpoint (fuzzer only)."),
    "graphql-scan": ("workflow", "GraphQL scan", "APIs", "host", "findings", "standard",
                     "Finds GraphQL endpoint(s) and audits each: introspection, CSRF, batching, verbose errors, "
                     "injection, exposed mutations."),
    "secrets-scan": ("workflow", "Secrets in JavaScript", "Secrets", "host", "findings", "standard",
                     "Collects the JS files a site uses (crawl + web archives) and scans each for API keys, "
                     "tokens and credentials."),
    "wayback-scan": ("workflow", "Scan archived URLs", "Web archive", "domain", "findings", "standard",
                     "Historical URLs from public web archives: old JS files scanned for secrets, every "
                     "parameterised URL scanned (fuzzer + nuclei DAST + sqlmap if SQLi)."),
    "wayback-fuzz": ("workflow", "Fuzz archived URLs", "Web archive", "domain", "findings", "standard",
                     "Historical URLs: secrets in JS files and the fuzzer on every parameterised URL (pass your "
                     "own payload with scan parameters: fuzz --payload ... --pattern ...)."),
    # ---- single tools (advanced) ---------------------------------------------------------------------------
    "subfinder": ("tool", "subfinder — passive subdomains", "Tools", "domain", "hosts", "quick",
                  "Subdomains of a domain from passive sources."),
    "dns-brute": ("tool", "DNS brute-force", "Tools", "domain", "hosts", "quick",
                  "Resolves <word>.<domain> for every word in the bundled subdomain wordlist."),
    "dnsx": ("tool", "dnsx — resolve hostnames", "Tools", "host", "hosts", "quick",
             "Keeps the hostnames that resolve in DNS."),
    "wayback-domains": ("tool", "Hostnames from web archives", "Tools", "domain", "hosts", "quick",
                        "Unique hostnames of a domain seen in public web archives."),
    "ping-scan": ("tool", "Ping sweep", "Tools", "network", "hosts", "quick",
                  "nmap -sn host discovery over an IP / CIDR / range."),
    "httpx": ("tool", "httpx — live web services", "Tools", "host", "urls", "quick",
              "Probes a host for live HTTP(S) services and returns their URLs."),
    "wayback": ("tool", "URLs from web archives", "Tools", "domain", "urls", "quick",
                "Historical URLs of a domain from four public archives."),
    "katana-crawl": ("tool", "katana — web crawler", "Tools", "url", "urls", "standard",
                     "Crawls a URL and returns the URLs found."),
    "harvest": ("tool", "Browser crawl (SPA)", "Tools", "url", "items", "standard",
                "Drives the site in headless Chromium and captures every request (incl. POST bodies)."),
    "js-endpoints": ("tool", "Endpoints from a JS file", "Tools", "js", "urls", "quick",
                     "Extracts API endpoint references from a JavaScript file."),
    "nuclei": ("tool", "nuclei — template scanner", "Tools", "host", "findings", "standard",
               "Runs nuclei against a host or URL (add your own -tags / -severity with extra arguments)."),
    "fuzz": ("tool", "Injection fuzzer", "Tools", "endpoint", "findings", "standard",
             "Fuzzes parameters / path / body for XSS, SQLi, SSTI, LFI, RCE, XXE, NoSQL and more."),
    "sqlmap": ("tool", "sqlmap — SQL injection", "Tools", "endpoint", "findings", "deep",
               "Tests a URL's parameters for SQL injection with sqlmap."),
    "scan-secrets": ("tool", "Secrets in a page / JS file", "Tools", "url", "findings", "quick",
                     "Fetches a URL and scans the response for exposed secrets (trufflehog + regex)."),
    "swagger-specs": ("tool", "Find OpenAPI specs", "Tools", "host", "urls", "quick",
                      "Probes common OpenAPI / Swagger paths on a host and lists the spec URLs."),
    "swagger-endpoints": ("tool", "Endpoints from an OpenAPI spec", "Tools", "spec", "urls", "quick",
                          "Lists the endpoint URLs an OpenAPI spec documents."),
    "graphql-detect": ("tool", "Find GraphQL endpoints", "Tools", "host", "urls", "quick",
                       "Probes common paths for a GraphQL endpoint."),
    "graphql-audit": ("tool", "GraphQL audit", "Tools", "graphql", "findings", "standard",
                      "Audits one GraphQL endpoint (introspection, CSRF, batching, injection, mutations)."),
    "liveless": ("tool", "liveless — reachable from the internet?", "Tools", "host", "urls", "quick",
                 "Asks an external probe (liveless.shrewdeye.app) whether each URL / host answers from the public "
                 "internet; only the reachable ones are passed on. The targets are sent to that service."),
    # ---- flow --------------------------------------------------------------------------------------------
    "merge": ("merge", "Merge", "Flow", "any", "items", "quick",
              "Combines the results of several steps, drops duplicates and passes each unique item on at once. "
              "Runs no job of its own."),
}


# ---- distributed versions of the composite workflows --------------------------------------------------------
# Each is a graph of single tools: every per-host / per-URL loop of the YAML recipe becomes a fan-out, so the
# items one step produces are spread as separate jobs over every scanner. Nothing is nested: a workflow shows
# every box it runs. Parallel steps come together in a MERGE (no job; duplicates dropped), hostnames found by
# passive discovery are verified by dnsx first, and SQL injection flagged by fuzz is confirmed by sqlmap.
#
# Every workflow that probes live services also ships an "-external" twin: a liveless check right after httpx
# (or on the targets, for the ones that start from a URL), so only what answers from the public internet is
# scanned.
HARVEST_DEEP = "--max-pages 0 --max-time 300 --max-actions 0"
NUCLEI_PASSES = [("exposures", "critical,high,medium,low"), ("misconfig", "critical,high,medium,low"),
                 ("cve2026", "critical,high,medium"), ("kev", "critical,high,medium"),
                 ("panel", "critical,high,medium")]
DAST = "--opt-args=-dast"


def st(t: str, frm=(SEED,), inp: str | None = None, args: str = "", label: str = "") -> dict:
    return {"t": t, "from": list(frm), "input": inp, "args": args, "label": label}


class WF:
    """Builds a stage list; add() returns the new step's index so steps can be wired by name."""

    def __init__(self):
        self.stages: list[dict] = []

    def add(self, t: str, frm=(SEED,), inp: str | None = None, args: str = "", label: str = "") -> int:
        self.stages.append(st(t, frm, inp, args, label))
        return len(self.stages) - 1


S = (SEED,)


def _entry(w: WF, ext: bool) -> tuple:
    """Where the live-probing steps of a URL-entry workflow read from: the targets, or only the reachable ones."""
    return (w.add("liveless", S, "all", label="liveless · reachable from the internet"),) if ext else S


def _discover(w: WF) -> int:
    """Domains -> verified hostnames: three discovery sources in parallel, merged, resolved by dnsx."""
    a = w.add("subfinder", S, "hosts")
    b = w.add("wayback-domains", S, "hosts")
    c = w.add("dns-brute", S, "hosts")
    m = w.add("merge", [SEED, a, b, c], "hosts", label="All discovered hostnames")
    return w.add("dnsx", [m], "hosts", label="dnsx · verify hostnames")


def _live(w: WF, hosts: int, ext: bool) -> int:
    """Hostnames -> live web services (URLs), optionally only the ones reachable from the internet."""
    h = w.add("httpx", [hosts], "all")
    return w.add("liveless", [h], "urls", label="liveless · reachable from the internet") if ext else h


def _nuclei(w: WF, src) -> None:
    for tag, sev in NUCLEI_PASSES:
        w.add("nuclei", src, "urls", f'--opt-args="-tags {tag} -severity {sev}"', f"nuclei · {tag}")


def _probe(w: WF, src, inp: str, what: str) -> int:
    """fuzz + nuclei DAST on parameterised URLs; returns the fuzz step (its SQLi hits are leads for sqlmap)."""
    f = w.add("fuzz", src, inp, "--timeout 120", f"Fuzz {what}")
    w.add("nuclei", src, inp, DAST, f"nuclei DAST · {what}")
    return f


def _web(w: WF, src, mode: str, extra_urls=()) -> None:
    """The deep scan of live URLs: crawl, then every parameter, request body, API and GraphQL endpoint and JS
    file. mode: scan (fuzz + nuclei DAST, sqlmap confirms SQLi) | fuzz (fuzzer only) | sqlmap (sqlmap only)."""
    k = w.add("katana-crawl", src, "urls")
    hv = w.add("harvest", src, "urls", HARVEST_DEEP, "Browser crawl (SPA)")
    crawl = w.add("merge", [k, hv], "all", label="Crawled URLs & requests")
    js = w.add("js-endpoints", [crawl], "js-urls")
    urls = w.add("merge", [crawl, js, *extra_urls], "all", label="All URLs")
    specs = w.add("swagger-specs", src, "urls")
    if mode == "scan":
        fp = _probe(w, [urls], "param-urls", "parameters")
        fw = w.add("fuzz", [crawl], "writes", "--timeout 120", "Fuzz POST/PUT bodies")
        ep = w.add("swagger-endpoints", [specs], "urls", label="API endpoints")
        epf = w.add("swagger-endpoints", [specs], "urls", "--fuzzable", "API endpoints (fuzzable)")
        fa = w.add("fuzz", [epf], "urls", "--timeout 120", "Fuzz API endpoints")
        w.add("nuclei", [ep], "urls", DAST, "nuclei DAST · API endpoints")
        w.add("sqlmap", [fp, fw, fa], "sql-leads", label="sqlmap · confirm SQL injection")
    elif mode == "fuzz":
        w.add("fuzz", [urls], "param-urls", "--timeout 120", "Fuzz parameters")
        w.add("fuzz", [crawl], "writes", "--timeout 120", "Fuzz POST/PUT bodies")
        epf = w.add("swagger-endpoints", [specs], "urls", "--fuzzable", "API endpoints (fuzzable)")
        w.add("fuzz", [epf], "urls", "--timeout 120", "Fuzz API endpoints")
    else:
        w.add("sqlmap", [urls], "param-urls", label="sqlmap · parameters")
        w.add("sqlmap", [crawl], "writes", label="sqlmap · POST/PUT bodies")
        ep = w.add("swagger-endpoints", [specs], "urls", label="API endpoints")
        w.add("sqlmap", [ep], "urls", label="sqlmap · API endpoints")
    gd = w.add("graphql-detect", src, "urls")
    w.add("graphql-audit", [gd], "urls")
    w.add("scan-secrets", [urls], "js-urls", label="Secrets in JS files")


def _wayback_lanes(w: WF, src, fuzz_only: bool = False) -> None:
    """Archived URLs: secrets in old JS files, every parameterised URL probed."""
    wb = w.add("wayback", src, "hosts")
    w.add("scan-secrets", [wb], "js-urls", label="Secrets in archived JS")
    if fuzz_only:
        w.add("fuzz", [wb], "param-urls", "--timeout 120", "Fuzz archived parameters")
        return
    f = _probe(w, [wb], "param-urls", "archived parameters")
    w.add("sqlmap", [f], "sql-leads", label="sqlmap · confirm SQL injection")


def _secrets(w: WF, src, archive_from=None) -> None:
    """JS files from a crawl (and the web archives) -> secrets."""
    k = w.add("katana-crawl", src, "urls")
    hv = w.add("harvest", src, "urls", HARVEST_DEEP, "Browser crawl (SPA)")
    ins = [k, hv]
    if archive_from is not None:
        ins.append(w.add("wayback", archive_from, "hosts"))
    m = w.add("merge", ins, "all", label="Crawled + archived URLs" if archive_from is not None else "Crawled URLs")
    w.add("scan-secrets", [m], "js-urls", label="Secrets in JS files")


def build(name: str, ext: bool = False) -> list[dict]:
    w = WF()
    if name == "web-full":
        h = _live(w, SEED, ext)
        _nuclei(w, [h])
        _web(w, [h], "scan")
    elif name in ("web-scan", "web-fuzz", "web-sqlmap"):
        _web(w, _entry(w, ext), name.split("-")[1])
    elif name == "web-nuclei":
        _nuclei(w, _entry(w, ext))
    elif name == "web-crawl":
        src = _entry(w, ext)
        k = w.add("katana-crawl", src, "urls")
        hv = w.add("harvest", src, "urls", HARVEST_DEEP, "Browser crawl (SPA)")
        w.add("merge", [k, hv], "all", label="All crawled URLs & requests")
    elif name == "spa-scan":
        src = _entry(w, ext)
        hv = w.add("harvest", src, "urls", HARVEST_DEEP, "Browser crawl (SPA)")
        fp = _probe(w, [hv], "param-urls", "parameters")
        fw = w.add("fuzz", [hv], "writes", "--timeout 120", "Fuzz POST/PUT bodies")
        w.add("sqlmap", [fp, fw], "sql-leads", label="sqlmap · confirm SQL injection")
        gd = w.add("graphql-detect", src, "urls")
        w.add("graphql-audit", [gd], "urls")
        w.add("scan-secrets", [hv], "js-urls", label="Secrets in JS files")
    elif name == "recon":
        _discover(w)
    elif name == "recon-http":
        _live(w, _discover(w), ext)
    elif name == "swagger-scan":
        specs = w.add("swagger-specs", _entry(w, ext), "all")
        ep = w.add("swagger-endpoints", [specs], "urls", label="API endpoints")
        epf = w.add("swagger-endpoints", [specs], "urls", "--fuzzable", "API endpoints (fuzzable)")
        fa = w.add("fuzz", [epf], "urls", "--timeout 120", "Fuzz API endpoints")
        w.add("nuclei", [ep], "urls", DAST, "nuclei DAST · API endpoints")
        w.add("sqlmap", [fa], "sql-leads", label="sqlmap · confirm SQL injection")
    elif name == "swagger-fuzz":
        specs = w.add("swagger-specs", _entry(w, ext), "all")
        epf = w.add("swagger-endpoints", [specs], "urls", "--fuzzable", "API endpoints (fuzzable)")
        w.add("fuzz", [epf], "urls", "--timeout 60", "Fuzz API endpoints")
    elif name == "graphql-scan":
        gd = w.add("graphql-detect", _entry(w, ext), "all")
        w.add("graphql-audit", [gd], "urls")
    elif name == "secrets-scan":
        src = _entry(w, ext)
        _secrets(w, src, archive_from=src)
    elif name == "wayback-scan":
        _wayback_lanes(w, S)
    elif name == "wayback-fuzz":
        _wayback_lanes(w, S, fuzz_only=True)
    elif name == "env-nuclei":
        _nuclei(w, [_live(w, _discover(w), ext)])
    elif name == "env-takeover":
        d = _discover(w)
        w.add("nuclei", [d], "hosts", '--opt-args="-tags takeover"', "nuclei · takeover")
    elif name == "env-secrets":
        _secrets(w, [_live(w, _discover(w), ext)])
    elif name == "env-wayback":
        _wayback_lanes(w, [_discover(w)])
    elif name == "env-wayback-secrets":
        d = _discover(w)
        h = _live(w, d, ext)
        _secrets(w, [h], archive_from=[h] if ext else [d])
    elif name == "env-scan":
        d = _discover(w)
        h = _live(w, d, ext)
        # archived URLs of every subdomain - or, internet-reachable only, of the hosts that answered
        wb = w.add("wayback", [h] if ext else [d], "hosts")
        _nuclei(w, [h])
        _web(w, [h], "scan", extra_urls=[wb])
    else:
        raise KeyError(name)
    return w.stages


# endpoint-scan (one conditional chain on one URL) and ip-discover (a single tool) have no fan-out to spread,
# so they run as one job per target and have no distributed version.
DISTRIBUTED_OF = ["web-full", "web-scan", "web-fuzz", "web-sqlmap", "web-nuclei", "web-crawl", "spa-scan", "recon",
                  "recon-http", "swagger-scan", "swagger-fuzz", "graphql-scan", "secrets-scan", "wayback-scan",
                  "wayback-fuzz", "env-nuclei", "env-takeover", "env-secrets", "env-wayback", "env-wayback-secrets",
                  "env-scan"]
# the ones that probe live services get an "only what is reachable from the internet" twin
EXTERNAL_OF = ["web-full", "web-scan", "web-fuzz", "web-sqlmap", "web-nuclei", "web-crawl", "spa-scan",
               "recon-http", "swagger-scan", "swagger-fuzz", "graphql-scan", "secrets-scan", "env-nuclei",
               "env-secrets", "env-wayback-secrets", "env-scan"]
DISTRIBUTED: dict[str, list[dict]] = {wf: build(wf) for wf in DISTRIBUTED_OF}
EXTERNAL: dict[str, list[dict]] = {wf: build(wf, ext=True) for wf in EXTERNAL_OF}


def distributed_name(name: str) -> str:
    return f"{name}-distributed"


def external_name(name: str) -> str:
    return f"{name}-external"


def _leaves_produce(stages: list[dict]) -> str:
    parents = {f for s in stages for f in s["from"] if f != SEED}
    kinds = {CATALOG[s["t"]][4] for i, s in enumerate(stages) if i not in parents} - {"findings"}
    if not kinds:
        return "findings"
    return kinds.pop() if len(kinds) == 1 else "items"


def _upsert(s: Session, name: str, **fields) -> Template:
    t = s.exec(select(Template).where(Template.name == name)).first()
    if t is None:
        t = Template(name=name, **fields)
    else:
        for k, v in fields.items():
            setattr(t, k, v)
    s.add(t)
    s.commit()
    s.refresh(t)
    return t


def seed_templates(s: Session) -> None:
    ids: dict[str, int] = {}
    for name, (kind, title, cat, accepts, produces, depth, desc) in CATALOG.items():
        t = _upsert(s, name, kind=kind, title=title, category=cat, accepts=accepts, produces=produces,
                    depth=depth, description=desc, builtin=True, variant_of="",
                    spec_json=json.dumps({"name": name, "params": []}))
        ids[name] = t.id
    wanted = set(CATALOG)

    def spec_of(stages):
        return {"stages": [{"template_id": ids[x["t"]], "from": x["from"],
                            "input": x["input"] or DEFAULT_INPUT.get(CATALOG[x["t"]][3], "all"),
                            "args": x["args"], "label": x.get("label", "")} for x in stages]}

    for wf, stages in DISTRIBUTED.items():
        kind, title, cat, accepts, _produces, depth, desc = CATALOG[wf]
        name = distributed_name(wf)
        wanted.add(name)
        _upsert(s, name, kind="pipeline", title=title, category=cat, accepts=accepts,
                produces=_leaves_produce(stages), depth=depth, builtin=True, variant_of=wf,
                description=f"{desc} Distributed: {len(stages)} steps, each fanned out over every scanner.",
                spec_json=json.dumps(spec_of(stages)))
    for wf, stages in EXTERNAL.items():
        kind, title, cat, accepts, _produces, depth, desc = CATALOG[wf]
        name = external_name(wf)
        wanted.add(name)
        _upsert(s, name, kind="pipeline", title=f"{title} — internet-reachable only", category=cat,
                accepts=accepts, produces=_leaves_produce(stages), depth=depth, builtin=True,
                variant_of=distributed_name(wf),
                description=f"{desc} Only what answers from the public internet is scanned: a liveless check "
                            f"(external probe) runs {'right after httpx' if any(x['t'] == 'httpx' for x in stages) else 'on the targets first'}. "
                            f"{len(stages)} steps.",
                spec_json=json.dumps(spec_of(stages)))
    # drop built-ins that no longer exist in this version (unless a scheduler still points at them)
    used = set(s.exec(select(Scheduler.template_id)).all())
    for t in s.exec(select(Template).where(Template.builtin == True)).all():  # noqa: E712
        if t.name not in wanted and t.id not in used:
            s.delete(t)
    s.commit()


def seed() -> None:
    with Session(engine) as s:
        ensure_admin(s)
        seed_templates(s)
        if settings.enroll_token:
            th = hash_token(settings.enroll_token)
            if not s.exec(select(EnrollToken).where(EnrollToken.token_hash == th)).first():
                s.add(EnrollToken(token_hash=th, label="built-in agent", prefix=settings.enroll_token[:6]))
        if not s.get(NotifySettings, 1):
            ns = NotifySettings(id=1)
            if settings.telegram_bot_token and settings.telegram_chat_id:
                ns.telegram_enabled = True
                ns.telegram_token = settings.telegram_bot_token
                ns.telegram_chat_id = settings.telegram_chat_id
            if settings.slack_webhook_url:
                ns.slack_enabled = True
                ns.slack_webhook = settings.slack_webhook_url
            s.add(ns)
        s.commit()

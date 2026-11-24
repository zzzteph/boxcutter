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
}


# ---- distributed versions of the composite workflows --------------------------------------------------------
# Each is a stage DAG: every outer per-host / per-URL loop of the YAML recipe becomes a fan-out, so the items
# one stage produces are spread as separate jobs over every scanner. Stages are written as
# st(template, from, input, args); `from` defaults to the scan's own targets.
HARVEST_DEEP = "--max-pages 0 --max-time 300 --max-actions 0"
NUCLEI_PASSES = [("exposures", "critical,high,medium,low"), ("misconfig", "critical,high,medium,low"),
                 ("cve2026", "critical,high,medium"), ("kev", "critical,high,medium"),
                 ("panel", "critical,high,medium")]


def st(t: str, frm=(SEED,), inp: str | None = None, args: str = "") -> dict:
    return {"t": t, "from": list(frm), "input": inp, "args": args}


def graft(sub: list[dict], parents: list[int], offset: int) -> list[dict]:
    """Re-root a sub-DAG: its entry stages read `parents` instead of the scan targets; indexes shift."""
    out = []
    for s in sub:
        frm: list[int] = []
        for f in s["from"]:
            frm += parents if f == SEED else [offset + f]
        out.append({**s, "from": frm})
    return out


def chain(base: list[dict], sub: list[dict], parents: list[int]) -> list[dict]:
    return base + graft(sub, parents, len(base))


def _web_nuclei():
    return [st("nuclei", inp="urls", args=f'--opt-args="-tags {tag} -severity {sev}"') for tag, sev in NUCLEI_PASSES]


def _web(mode: str):
    s = [st("katana-crawl", inp="urls"),                          # 0
         st("harvest", inp="urls", args=HARVEST_DEEP),            # 1
         st("js-endpoints", [0, 1], "js-urls")]                   # 2
    if mode == "scan":
        s += [st("endpoint-scan", [0, 1, 2], "param-urls"),       # 3
              st("fuzz", [1], "writes", "--timeout 120"),         # 4
              st("swagger-specs", inp="urls"),                    # 5
              st("swagger-scan", [5], "urls")]                    # 6
    elif mode == "fuzz":
        s += [st("fuzz", [0, 1, 2], "param-urls", "--timeout 120"),
              st("fuzz", [1], "writes", "--timeout 120"),
              st("swagger-specs", inp="urls"),
              st("swagger-endpoints", [5], "urls", "--fuzzable"),
              st("fuzz", [6], "urls", "--timeout 120")]
    else:  # sqlmap
        s += [st("sqlmap", [0, 1, 2], "param-urls"),
              st("sqlmap", [1], "writes"),
              st("swagger-specs", inp="urls"),
              st("swagger-endpoints", [5], "urls"),
              st("sqlmap", [6], "urls")]
    gd = len(s)
    s += [st("graphql-detect", inp="urls"),
          st("graphql-audit", [gd], "urls"),
          st("scan-secrets", [0, 1], "js-urls")]
    return s


def _recon():
    return [st("subfinder", inp="hosts"), st("wayback-domains", inp="hosts"), st("dns-brute", inp="hosts"),
            st("dnsx", [SEED, 0, 1, 2], "hosts")]


def _secrets():
    return [st("katana-crawl", inp="urls"), st("harvest", inp="urls", args=HARVEST_DEEP),
            st("wayback", inp="hosts"), st("scan-secrets", [0, 1, 2], "js-urls")]


def _wayback(consumer: str):
    return [st("wayback", inp="hosts"), st("scan-secrets", [0], "js-urls"), st(consumer, [0], "param-urls")]


def _subs():
    return [st("subfinder", inp="hosts"), st("dns-brute", inp="hosts")]


def _web_full():
    return chain(chain([st("httpx", inp="all")], _web_nuclei(), [0]), _web("scan"), [0])


DISTRIBUTED: dict[str, list[dict]] = {
    "web-full": _web_full(),
    "web-scan": _web("scan"),
    "web-fuzz": _web("fuzz"),
    "web-sqlmap": _web("sqlmap"),
    "web-nuclei": _web_nuclei(),
    "web-crawl": [st("katana-crawl", inp="urls"), st("harvest", inp="urls", args=HARVEST_DEEP)],
    "spa-scan": [st("harvest", inp="urls", args=HARVEST_DEEP), st("endpoint-scan", [0], "param-urls"),
                 st("fuzz", [0], "writes", "--timeout 120"), st("graphql-detect", inp="urls"),
                 st("graphql-audit", [3], "urls"), st("scan-secrets", [0], "js-urls")],
    "recon": _recon(),
    "recon-http": _recon() + [st("httpx", [3], "hosts")],
    "swagger-scan": [st("swagger-specs", inp="all"), st("swagger-scan", [0], "urls")],
    "swagger-fuzz": [st("swagger-specs", inp="all"), st("swagger-endpoints", [0], "urls", "--fuzzable"),
                     st("fuzz", [1], "urls", "--timeout 60")],
    "graphql-scan": [st("graphql-detect", inp="all"), st("graphql-audit", [0], "urls")],
    "secrets-scan": _secrets(),
    "wayback-scan": _wayback("endpoint-scan"),
    "wayback-fuzz": _wayback("fuzz"),
    "env-nuclei": chain(_subs() + [st("httpx", [0, 1], "hosts")], _web_nuclei(), [2]),
    "env-takeover": _subs() + [st("nuclei", [0, 1], "hosts", '--opt-args="-tags takeover"')],
    "env-secrets": chain(_recon() + [st("httpx", [3], "hosts")], _secrets(), [4]),
    "env-wayback": _subs() + [st("wayback", [0, 1], "hosts"), st("endpoint-scan", [2], "param-urls")],
    "env-wayback-secrets": chain(_subs(), _secrets(), [0, 1]),
    "env-scan": chain(chain(_recon(), _web_full(), [3]), _wayback("endpoint-scan"), [3]),
}
# endpoint-scan (one conditional chain on one URL) and ip-discover (a single tool) have no fan-out to spread,
# so they run as one job per target and have no distributed version.


def distributed_name(name: str) -> str:
    return f"{name}-distributed"


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
    for wf, stages in DISTRIBUTED.items():
        kind, title, cat, accepts, _produces, depth, desc = CATALOG[wf]
        spec = {"stages": [{"template_id": ids[x["t"]], "from": x["from"],
                            "input": x["input"] or DEFAULT_INPUT.get(CATALOG[x["t"]][3], "all"),
                            "args": x["args"]} for x in stages]}
        name = distributed_name(wf)
        wanted.add(name)
        _upsert(s, name, kind="pipeline", title=title, category=cat, accepts=accepts,
                produces=_leaves_produce(stages), depth=depth, builtin=True, variant_of=wf,
                description=f"{desc} Distributed: {len(stages)} steps, each fanned out over every scanner.",
                spec_json=json.dumps(spec))
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

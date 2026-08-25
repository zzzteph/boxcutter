"""First-boot seed: the admin user (root/root, must change password), the dev enroll token, a demo LLM
profile, and a starter set of templates (workflows, tools, agents) so the app is usable out of the box.

Everything here is idempotent - re-running skips anything that already exists by name (but backfills the
official description onto older rows that predate the description column).

Descriptions are the stock engine's own text (boxcutter --list-all / workflow --list / ai --list) so the
picker reads exactly like the CLI's help."""
from __future__ import annotations

import json

from sqlmodel import Session, select

from .config import settings
from .db import engine
from .models import EnrollToken, LLMProfile, NotifySettings, Template, User
from .security import hash_password, hash_token

# The real stock boxcutter catalog {name: official description}.
TOOLS = {
    "subfinder": "Discover subdomains of a target domain using Subfinder.",
    "dnsx": "Resolve names, brute-force a domain (--domain --wordlist), and filter wildcards (--wildcard). A/AAAA/CNAME; --resp adds the record.",
    "dns-brute": "Brute-force a domain's subdomains with boxcutter's bundled wordlist (wraps dnsx). Give just the domain; --wordlist overrides the default.",
    "httpx": "Probe a target with httpx to detect live HTTP services.",
    "api-map": "Method-aware API discovery: enumerate paths x {GET,POST,PUT,PATCH,DELETE,OPTIONS}, diff each vs a per-method catch-all, and report which paths exist for which verbs (write verbs first). Non-destructive.",
    "smart-enum": "Generate a context-aware candidate path list from observed URLs (version pivots, numeric id-walks, singular/plural, high-value siblings under observed prefixes). Non-touching; pipe into path-bust/api-map/ffuf.",
    "screenshot": "Take a screenshot of a target URL using httpx (headless chromium).",
    "wayback": "Pull historical URLs for a domain from 4 public archives (deduped).",
    "wayback-domains": "Run wayback (subdomains on) and extract the unique host list.",
    "katana-crawl": "Crawl a target URL with Katana (supports --js / --params filters).",
    "zap-crawl": "Crawl a target URL with ZAP AJAX + traditional spider.",
    "js-endpoints": "Fetch a JavaScript file and extract API endpoint references via regex.",
    "harvest": "Deep browser crawler: drive the app (click/submit/SPA), capture every request, dedupe into a corpus.",
    "browser-login": "Log in through a real browser (SPA/CSRF/redirect) and return the resulting session cookie/token.",
    "browser-actions": "Drive a headless browser through scripted actions (click/type/select/...) and capture the result.",
    "visual-driver": "Drive a browser by SCREEN COORDINATES with human-like mouse motion + typing; returns a coordinate-grid screenshot each call.",
    "vision-verify": "Load a URL in headless chromium and report whether JS actually EXECUTED (alert/console/canary captured) vs merely reflected - confirms reflected/DOM XSS and screenshots the proof.",
    "nuclei": "Run Nuclei vulnerability scanner against a target.",
    "sqlmap": "Run sqlmap SQL injection scanner against a target URL.",
    "blind-oracle": "Detect blind SQL / OS-command injection across a request's parameters via boolean + time-based differential probes (session-aware, delay-scaling confirmation, non-destructive).",
    "bola-walk": "Two-session cross-account authorization diff (BOLA/IDOR): walk an object id and report where identity B reads an access-controlled object that isn't B's. 3-way (unauth/A/B) test, non-destructive.",
    "mass-assign": "Detect mass-assignment: re-send a write body with privileged attributes injected (role=admin, isAdmin, verified, balance, ...) and flag acceptance (echoed, or confirmed via --verify). Non-destructive to others.",
    "dirb": "Brute-force directories on a target URL with dirb.",
    "dirsearch": "Brute-force directories on a target URL with dirsearch.",
    "zap-scan-url": "ZAP active scan against a single exact URL (no crawling).",
    "zap-scan-full": "Full ZAP scan: spider + AJAX spider + active scan against a target URL.",
    "zap-scan-openapi": "ZAP active scan driven by an OpenAPI/Swagger specification URL.",
    "path-fuzz": "Brute-force a FUZZ position in a URL; content/structure gate keeps only real, distinct paths (200 by default).",
    "path-bust": "Directory brute-force under a URL path (no FUZZ marker); content/structure gate, per-dir calibration, --depth.",
    "fuzz": "Fuzz params/path/body for injection (XSS, SQLi, SSTI, LFI, RCE, XXE, NoSQL, GraphQL) or enumerate IDs.",
    "scan-secrets": "Fetch a URL and scan the response body for exposed secrets/credentials.",
    "git-extract": "Extract source from an exposed .git directory and scan it for secrets.",
    "swagger-parser": "Fetch and parse an OpenAPI/Swagger spec into a structured endpoint list.",
    "swagger-endpoints": "List endpoint URLs from an OpenAPI/Swagger spec (--fuzzable for {FUZZ}-marked variants).",
    "swagger-specs": "Probe common OpenAPI/Swagger paths on a host and list the spec URLs found.",
    "graphql-detect": "Probe common paths for a GraphQL endpoint and list the URL(s) found.",
    "graphql-audit": "Audit a GraphQL endpoint: introspection, CSRF, batching, verbose errors, arg injection, mutation exposure.",
    "http-request": "Make an HTTP request to a target URL (POST if --data/-D given, else GET; -X sets any method).",
}
WORKFLOWS = {
    "endpoint-scan": "scan one endpoint with every DAST tool - fuzz + nuclei -dast + sqlmap + zap-scan-url",
    "env-nuclei": "subfinder + dns-brute -> nuclei across the env (takeover on all hosts; web-nuclei template passes on live hosts)",
    "env-scan": "enumerate + validate subdomains, then web-full + wayback-scan each (web-full probes liveness itself)",
    "env-secrets": "env-scan without the vuln scanners - validate subdomains, then crawl + secrets-scan each live host",
    "env-takeover": "subfinder + dns-brute, then nuclei takeover templates on every discovered subdomain",
    "env-wayback-secrets": "subfinder + dns-brute, then secrets-scan (web-crawl + wayback -> scan-secrets) on every subdomain",
    "env-wayback": "subfinder + dns-brute, wayback every subdomain, then endpoint-scan every parameterised URL (deduped)",
    "graphql-scan": "discover GraphQL endpoint(s) on a target, then audit each (introspection, CSRF, batching, injection, mutation exposure)",
    "recon-http": "recon, then httpx; show only the live HTTP(S) services",
    "recon": "subdomains (subfinder + wayback + dns-brute), kept if they resolve (dnsx)",
    "secrets-scan": "gather JS files (web-crawl + wayback, filtered to JS), scan each for secrets",
    "spa-scan": "browser-crawl a JS/SPA in real Chromium (clicks, submits, captures every request incl. the cross-origin API), then DAST each endpoint - endpoint-scan (fuzz + nuclei-dast + sqlmap + zap-scan-url) on each param URL, the body of each POST/PUT fuzzed too, plus GraphQL audit and secrets on JS",
    "swagger-fuzz": "find OpenAPI/Swagger spec(s) on a host (or use a spec URL), then fuzz every parameterised endpoint (fuzz only - sibling of web-fuzz)",
    "swagger-scan": "find OpenAPI/Swagger spec(s) on a host (or scan a spec URL directly), then DAST every endpoint - fuzz (fuzzable) + nuclei-dast + sqlmap + zap-scan-url per endpoint, plus zap-scan-openapi per spec",
    "wayback-fuzz": "wayback URLs - scan-secrets on JS, then fuzz each parameterised URL with YOUR payload (--arg fuzz=\"--payload ... --pattern ...\")",
    "wayback-scan": "wayback URLs - secrets on JS files, sqlmap/fuzz/zap on param URLs",
    "web-crawl": "crawl a URL with Katana + ZAP + harvest (real-browser, SPA-aware), merged - emits the endpoint CORPUS (URL strings from the spiders + method/url/body objects from harvest). Project it with ${crawl | urls} for URLs, or ${crawl | writes} for the POST/PUT endpoints.",
    "web-full": "probe liveness (httpx), then nuclei template passes + the full web-scan DAST on each live URL",
    "web-fuzz": "like web-scan but injection testing is fuzz-only - no sqlmap, no ZAP active scan. crawl -> fuzz per param URL -> swagger -> fuzz per endpoint -> graphql detect+audit -> secrets per JS",
    "web-nuclei": "nuclei template passes against one URL - exposures, misconfig, cve2026, kev, exposed-panels (each with tuned severity)",
    "web-scan": "full DAST of one known URL (no httpx probe) - crawl -> zap-full -> endpoint-scan per param URL -> swagger -> graphql-scan -> secrets per JS",
    "web-sqlmap": "like web-scan but injection testing is sqlmap-only - no fuzz, no ZAP active scan. crawl -> sqlmap per param URL -> swagger -> sqlmap per endpoint -> graphql detect+audit -> secrets per JS",
}
AGENTS = {
    "irvin": "Conductor: travis -> bob -> caleb, verified + consolidated, with a CEO report and per-agent reasoning.",
    "logio": "Standalone agentic login: an auth-only agent that logs in with supplied creds (no IRVIN pipeline).",
    "prawlio": "Authenticated crawl: log in with logio, then crawl the app under that session and list the URLs found.",
    "crawlio": "Single-agent crawler: build a comprehensive, code-verified endpoint list (strict about false/ghost paths).",
    "juicy": "Single-agent JS analyst: from a JS file or page, extract hidden URLs, find DOM XSS + secrets, with PoCs.",
    "bob": "Bob - short surface scanner: an LLM agent that drives the boxcutter tools to highlight exposed surface.",
    "travis": "Travis - recon triage: probe ONE host lightly and rate how interesting it is for a deeper scan (bob).",
    "caleb": "Caleb - multi-phase / multi-identity orchestrator: authenticated deep scan, reauth, two-account BFLA, and multi-step chains (reuses bob as its scanning muscle).",
}
DEMO_PROFILE = "demo (set an API key)"
AGENT_CONTEXT = "Authorized assessment. Report only real, exploitable issues."


def _ensure_template(s: Session, name: str, kind: str, spec_name: str, owner_id: int, description: str = "",
                     llm_profile_id: int | None = None, context: str | None = None) -> None:
    existing = s.exec(select(Template).where(Template.name == name)).first()
    if existing:
        # backfill the official description onto rows created before the column existed
        if description and not (existing.description or "").strip():
            existing.description = description
            s.add(existing)
        return
    s.add(Template(name=name, kind=kind, spec_json=json.dumps({"name": spec_name, "flags": []}),
                   description=description, context=context, llm_profile_id=llm_profile_id, owner_id=owner_id))


def seed() -> None:
    with Session(engine) as s:
        admin = s.exec(select(User).where(User.username == settings.admin_user)).first()
        if not admin:
            admin = User(username=settings.admin_user, password_hash=hash_password(settings.admin_password),
                         role="admin", must_change_password=True)
            s.add(admin)
            s.commit()
            s.refresh(admin)

        if settings.enroll_token:
            th = hash_token(settings.enroll_token)
            if not s.exec(select(EnrollToken).where(EnrollToken.token_hash == th)).first():
                s.add(EnrollToken(token_hash=th, label="seed (from .env)"))

        # a placeholder LLM profile so the agent templates are visible; set a real key to run them for real
        profile = s.exec(select(LLMProfile).where(LLMProfile.name == DEMO_PROFILE)).first()
        if not profile:
            profile = LLMProfile(name=DEMO_PROFILE, provider="anthropic", model="claude-sonnet-5",
                                 api_key_secret="", created_by=admin.id)
            s.add(profile)
            s.commit()
            s.refresh(profile)

        for name, desc in WORKFLOWS.items():
            _ensure_template(s, name, "workflow", name, admin.id, description=desc)
        for name, desc in TOOLS.items():
            _ensure_template(s, name, "tool", name, admin.id, description=desc)
        for name, desc in AGENTS.items():
            _ensure_template(s, name, "ai_agent", name, admin.id, description=desc,
                             llm_profile_id=profile.id, context=AGENT_CONTEXT)

        # Telegram notification settings singleton — seed from env if a bot token/chat id were provided
        if not s.exec(select(NotifySettings)).first():
            ns = NotifySettings(id=1)
            if settings.telegram_bot_token and settings.telegram_chat_id:
                ns.telegram_enabled = True
                ns.telegram_token = settings.telegram_bot_token
                ns.telegram_chat_id = settings.telegram_chat_id
            s.add(ns)
        s.commit()

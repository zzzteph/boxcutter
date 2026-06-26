"""Lateral - the deep-dive agent. Turns footholds into reach across the application."""

from ..base import Agent


class Lateral(Agent):
    name = "lateral"
    tools = {"http-request", "fuzz", "sqlmap", "dirsearch", "js-endpoints", "git-extract", "scan-secrets",
             "swagger-endpoints", "graphql-audit", "browser-crawl", "browser-actions"}
    max_steps = 26

    def should_run(self, ctx):
        harvested = any(k.startswith("H") for k in ctx.identities)
        return bool(harvested or ctx.secrets or ctx.surface.get("endpoints"))

    def objective(self, ctx):
        return (
            "You are LATERAL MOVEMENT / DEEP DIVE. By now the context holds footholds - harvested identities "
            "(H* tokens/cookies), leaked secrets, admin/panel/.git paths, and discovered endpoints. Your job is "
            "to PIVOT off each one and reach deeper into the app until you hit real impact:\n"
            "- AUTHENTICATED SWEEP: with the strongest harvested identity, re-walk the surface - re-request "
            "everything that returned 401/403 unauthenticated, and pull every endpoint the spec/JS exposes.\n"
            "- HORIZONTAL: swap identities / tenant-ids / object-ids to read another user's or org's data (BOLA); "
            "quote a field that proves the record isn't yours.\n"
            "- VERTICAL: reach an admin-only sensitive_action (from the APP PROFILE) as a normal/low-priv identity "
            "(BFLA), or escalate via mass-assignment / role tampering on a single request.\n"
            "- DIG INTO PANELS: for every admin/panel/dashboard/api dir in the surface, `dirsearch <base>/<dir>/` "
            "and `http-request` its index/login (/admin/index.php, /admin/login.php) - a dir whose root looks "
            "static (a placeholder image, a welcome page) usually HIDES the real app one level in; never accept a "
            "static index as 'nothing here'.\n"
            "- MINE LEAKS: from any .git dump, config, JS, or verbose error, extract NEW endpoints, hosts, and "
            "secrets (`git-extract`, `scan-secrets`, `js-endpoints`) and immediately act on them - dirsearch new "
            "paths, fuzz new params, request new endpoints with the harvested session.\n"
            "- CHAIN COMPONENTS: admin -> panel -> exposed source/config -> new endpoints/subdomains -> repeat.\n"
            "Record every NEW credential/endpoint you reach under artifacts so the reporter can chain it. Keep "
            "pivoting until you run out of leads. Respect the RULES line; flag (don't run) any crack/brute/RCE step.\n"
            "Clever: REUSE the harvested credential on OTHER subdomains/services (one SSO token often unlocks many "
            "hosts); act on internal hostnames you leaked; turn a low-priv read that exposes an id into a "
            "high-priv action; and follow refresh tokens to keep the foothold alive.")

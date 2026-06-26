"""JS-analyzer - mines JavaScript for hidden endpoints, secrets, and logic hints."""

from ..base import Agent


class JsAnalyzer(Agent):
    name = "js-analyzer"
    tools = {"js-endpoints", "scan-secrets", "http-request"}
    max_steps = 16

    def should_run(self, ctx):
        return bool(ctx.surface.get("js"))

    def objective(self, ctx):
        return (
            "You are JS-ANALYZER. JavaScript bundles leak how the app really works - mine every JS file on the "
            "surface:\n"
            "- `js-endpoints <jsfile>` to pull hidden API paths, parameter names, and admin/internal routes no "
            "page links to.\n"
            "- `scan-secrets <jsfile>` for keys/tokens/credentials (report REDACTED to pattern+location).\n"
            "- `http-request` a JS file directly to read inline config, feature flags, CLIENT-SIDE role/permission "
            "checks, and comments - these reveal the app's logic: which endpoints exist, which params matter, and "
            "what the client THINKS is allowed (often enforced only client-side -> a real bug to test server-side).\n"
            "Feed it forward: new endpoints in artifacts.endpoints (recon-ranker/fuzzer/access act on them), any "
            "credential in artifacts.tokens. Report leaked secrets and client-only authz hints as findings.\n"
            "Clever: pull `.map` source maps to recover original source; grab API base URLs for OTHER environments "
            "(staging/internal); treat client-side role/feature checks (isAdmin, canEdit) as server-side test "
            "targets; and note commented-out or disabled endpoints.")

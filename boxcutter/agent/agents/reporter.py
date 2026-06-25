"""Reporter — verifies every candidate, correlates chains, writes the boxcutter report."""

from ..base import Agent


class Reporter(Agent):
    name = "reporter"
    tools = {"http-request", "fuzz", "nuclei", "git-extract", "scan-secrets"}
    max_steps = 24
    emits_report = True

    def context_block(self, ctx):
        return ctx.brief() + "\n\nCANDIDATE FINDINGS (verify before reporting):\n" + ctx.findings_dump()

    def objective(self, ctx):
        return (
            "You are REPORTER. Two jobs, then the report.\n"
            "1) VERIFY: for each candidate finding, re-run its reproduce argv via run_boxcutter (e.g. "
            "`http-request <url> --header ...`, or `fuzz <url> --payload \"<input>\" --pattern \"REGEX\"`). Keep "
            "only those with verbatim, real-impact evidence; drop or downgrade the rest. Never invent evidence.\n"
            "2) CORRELATE: stitch confirmed findings into multi-stage attack chains (foothold -> escalate -> "
            "impact), and report the chain at its combined severity. Known web chain patterns to look for:\n"
            "   - swagger/test/debug endpoint -> leaks a JWT/key -> authenticated API -> BOLA + mass-assignment + SQLi\n"
            "   - info leak (JS / .git / config / verbose error) -> credential or how IDs/hashes are built -> "
            "authenticated access -> IDOR / auth bypass  [offline crack = manual]\n"
            "   - exposed admin -> panel -> exposed /.git or source -> new endpoints/secrets -> deeper access\n"
            "   - self-registration -> mass-assignment of a privileged role -> BFLA / admin actions\n"
            "   - open management UI / default-cred panel -> RCE-lead  [login brute / RCE-exec = manual]\n"
            "   Rate impact using the APP PROFILE - an unauth/cross-tenant hit on a sensitive_action in a "
            "fintech/healthcare app is Critical/High; the same on a brochure site is not.\n\n"
            "Then OUTPUT THE FINAL REPORT as plain text (NO json block):\n"
            "  SCAN REPORT: <target>   MODE: <mode>   DATE: <date>\n"
            "  TESTED: <surface/identities/fuzz/exposure counts>\n"
            "  FINDINGS: one line each — [VULN:High|Medium] or [SUGGESTION] <title> | Reproduce: <boxcutter argv> "
            "| Evidence: <=100 chars\n"
            "  CHAINS: each chain as link -> link -> impact (or 'none')\n"
            "  COVERAGE: what was/wasn't tested; out of scope -> manual: auth-flows, SSRF/CSRF, stateful logic, "
            "credential-cracking/brute-force/RCE-exec (no boxcutter tool)\n"
            "  SUMMARY: Vulns N (High n, Medium n) | Suggestions n")

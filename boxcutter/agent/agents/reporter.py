"""Reporter - assembles the professional report. Validation + chaining already happened upstream."""

from ..base import Agent


class Reporter(Agent):
    name = "reporter"
    tools = {"http-request"}
    max_steps = 12
    emits_report = True

    def context_block(self, ctx):
        return ctx.brief() + "\n\nFINDINGS (status set by validator; chains by correlator):\n" + ctx.findings_dump()

    def objective(self, ctx):
        return (
            "You are REPORTER. Validation is DONE (each finding has a status) and chains are built (cls=chain). "
            "Do NOT re-test - assemble the professional report. Map status -> section: confirmed -> a VULNERABILITY "
            "entry at its severity; downgraded -> a SUGGESTION entry; dropped -> omit. Order by severity "
            "(Critical, High, Medium, Low).\n"
            "Findings with status 'unverified' (evidence NOT found in any captured response) are reported at most "
            "as [SUGGESTION], never [VULN]. A machine-generated VERIFIED RUN FACTS block is printed after your "
            "report - never claim more coverage or more confirmed findings than it shows.\n\n"
            "Write each VULNERABILITY as a professional bug-bounty report entry (HackerOne style):\n"
            "### [<SEVERITY>] <concise, asset-specific title>\n"
            "- **Weakness:** <class - e.g. IDOR / BOLA, SQL Injection, Authentication Bypass, Sensitive Data Exposure>\n"
            "- **Affected:** <URL / endpoint / parameter>\n"
            "- **Description:** <what the flaw is and why it exists, 1-3 sentences>\n"
            "- **Steps to Reproduce:**\n  1. <exact boxcutter command, including the identity --header if needed>\n  2. ...\n"
            "- **Proof / Evidence:** `<verbatim <=100-char redacted excerpt>`\n"
            "- **Impact:** <concrete business impact, grounded in the APP PROFILE>\n"
            "- **Remediation:** <the specific fix>\n\n"
            "SUGGESTIONS: list downgraded items as one-liners (title | why follow up | reproduce).\n\n"
            "Then close with:\n"
            "## Scan summary\n"
            "- **Target / Mode / Date:** <target> | <mode> | <date>\n"
            "- **Tested:** <surface / identities / fuzz / exposure counts>\n"
            "- **Chains:** <each cls=chain finding as link -> link -> impact, at combined severity> (or 'none')\n"
            "- **Coverage:** what was and wasn't tested; name agents the coordinator skipped; OUT OF SCOPE -> "
            "manual: SSRF/CSRF/open-redirect, authenticated login/OAuth/MFA flows, stateful logic, infra "
            "(ports / subdomain-takeover / CORS)\n"
            "- **Totals:** Critical <n> | High <n> | Medium <n> | Low <n> | Suggestions <n>\n"
            "- **Note:** automated findings need human validation; not all are exploitable in context.\n"
            "Clever: frame each impact around the app's crown-jewel object / threat model, and collapse the same "
            "bug across many params into ONE finding with representative examples rather than N near-duplicates.")

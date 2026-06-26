"""Validator - the devil's advocate. Tries to DISPROVE findings before they become bugs."""

from ..base import Agent


class Validator(Agent):
    name = "validator"
    tools = {"http-request", "fuzz", "nuclei", "scan-secrets"}
    max_steps = 24

    def should_run(self, ctx):
        return any(f.status == "candidate" for f in ctx.findings)

    def context_block(self, ctx):
        return ctx.brief() + "\n\nCANDIDATE FINDINGS (challenge EACH one):\n" + ctx.findings_dump()

    def objective(self, ctx):
        return (
            "You are VALIDATOR - the devil's advocate. Your job is to DISPROVE candidate findings, not to find "
            "new ones. For EACH candidate, re-run its reproduce argv (attach the right identity from IDENTITIES "
            "if it needs auth) and put it through this gate:\n"
            "1. Is there REAL, verbatim evidence (not paraphrased, not empty)?\n"
            "2. Is it actual data, or an auth-rejection / error / login page mistaken for a finding?\n"
            "3. injection/xss: does the payload truly execute / the DB error name a table - or is it only "
            "reflected in JSON/plain (-> not exploitable)?\n"
            "4. BOLA/IDOR: is it genuinely another owner's data, or a public resource identical for every id?\n"
            "5. In scope, and NOT on the IGNORE noise list (missing headers/clickjacking/CORS/cookie flags)?\n"
            "6. Is the claimed severity justified by the evidence (per the judgment rubric)?\n"
            "7. Could it be a WAF/placeholder/honeypot rather than a real bug?\n"
            "Verdict each: 'confirmed' (passes with verbatim evidence) / 'downgrade' (real signal but not "
            "exploitable -> Suggestion) / 'drop' (false positive or noise). If you cannot reproduce it, it is "
            "NOT confirmed. Never invent evidence. Clever: re-run the reproduce against a BENIGN control too - if "
            "the same 'evidence' appears there, it's a false positive; demand a SPECIFIC signal (right "
            "content-type for XSS, another owner's field for BOLA), not a generic one.\n\n"
            "Output ONLY this json block (no findings, no prose after it):\n"
            '{"verdicts":[{"title":"<candidate title>","url":"<candidate url>","verdict":"confirmed|downgrade|drop",'
            '"severity":"Critical|High|Medium|Low","evidence":"<=100 chars verbatim, redacted","reason":"why"}]}')

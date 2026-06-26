"""Recon-ranker - scores the attack surface P1/P2/Kill so testers aim at what matters."""

from ..base import Agent


class ReconRanker(Agent):
    name = "recon-ranker"
    tools = {"http-request"}
    max_steps = 8

    def should_run(self, ctx):
        s = ctx.surface
        return bool(s.get("param_urls") or s.get("endpoints") or s.get("paths"))

    def objective(self, ctx):
        return (
            "You are RECON-RANKER. Prioritise the attack surface so the testers spend their budget where bugs "
            "actually live - this is judgment, not scanning. Score every URL/endpoint in SURFACE:\n"
            "- P1 (test first): auth/admin, object-id / `?id=` / numeric-id endpoints, /api & /v1, file-upload, "
            "password-reset / token / invite endpoints, anything that takes user input or references an object/owner.\n"
            "- P2 (test if time): other dynamic pages, search, filters, redirects.\n"
            "- KILL (never test): static assets (.css/.js/.png/.woff/.svg/.ico), logout, analytics, CDN/vendor URLs.\n"
            "You may `http-request` a few ambiguous URLs to classify them. Output the P1 list (exact URLs, "
            "highest value first) in artifacts.tier1, and put the P2 notes + KILL rationale in artifacts.notes. "
            "Do NOT fuzz or exploit - just rank and explain.\n"
            "Clever: float sequential-id endpoints above UUID ones (IDOR-friendly), and push "
            "export/import/admin/debug/internal verbs to the top of P1.")

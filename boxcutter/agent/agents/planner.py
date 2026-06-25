"""Planner - the decision engine. Orients on the target and sets the strategy for the run."""

from ..base import Agent


class Planner(Agent):
    name = "planner"
    tools = {"httpx", "http-request"}
    max_steps = 8

    def objective(self, ctx):
        return (
            "You are the PLANNER / decision engine. You don't test for bugs - you orient the whole run so the "
            "deeper agents aim at the right things.\n\n"
            "PLAYBOOK:\n"
            "1. Confirm a live BASE URL: `httpx <target>` for a bare domain, or `http-request <target>` if it "
            "already has a scheme. Note the final URL after redirects, the server/framework headers, and whether "
            "http and https both serve.\n"
            "2. Classify the ENTRY SHAPE from what you see: bare domain (needs full recon) / single URL / API "
            "base (json responses, /api, /v1) / OpenAPI-or-Swagger spec / GraphQL.\n"
            "3. Decide which stages matter and any knobs: is there likely an API or spec (-> api agent), a CMS or "
            "known stack (-> fingerprint tags), an auth surface (-> access/lateral)? Pick a sensible nuclei "
            "severity/tag focus and flag scope cautions (WAF/CDN headers, obvious production data, rate limits).\n\n"
            "USE CONTEXT: you usually run first - the only inputs are the target and any provided IDENTITIES.\n"
            "HAND OFF: confirmed live BASE URL(s) in artifacts.endpoints; in artifacts.notes put the entry shape, "
            "the ordered plan (which stages matter and why), knob choices, and cautions. Keep it tight - one orient "
            "pass, then stop. Do not deep-crawl; discovery does that.")

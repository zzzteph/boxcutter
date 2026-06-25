"""Profile — builds a shared model of WHAT THE APPLICATION IS, so later agents test what matters.

This closes bob's app-comprehension gap: instead of generic business-rule guesses, the access and
fuzzer agents get a concrete model of the app's purpose, roles, key objects, and sensitive actions.
The model (a richer take on hexstrike's TargetProfile) is written to ctx.app_profile and shows up in
every downstream agent's prompt via ctx.brief().
"""

from ..base import Agent


class Profile(Agent):
    name = "profile"
    tools = {"http-request", "httpx"}
    max_steps = 8

    def objective(self, ctx):
        return (
            "You are PROFILE. Understand WHAT THIS APPLICATION IS so the later agents test what actually "
            "matters. Fetch a few representative pages with `http-request` — the homepage, any "
            "login/dashboard/api index, and 1-2 key endpoints from the surface — and read titles + content. "
            "Then synthesize a model of the app from evidence you actually saw.\n\n"
            "Output your normal json block AND a top-level \"profile\" object:\n"
            '  "profile": {\n'
            '    "purpose": "<one line: what the app does for whom>",\n'
            '    "domain": "fintech|ecommerce|healthcare|saas|cms|gov|social|devtools|...",\n'
            '    "target_type": "web_application|api|spa|admin_panel|...",\n'
            '    "tech": "<stack if known>",\n'
            '    "roles": ["anonymous","user","admin","org-admin",...],\n'
            '    "key_objects": ["order","account","invoice","transfer",...],\n'
            '    "sensitive_actions": ["POST /api/payments","PUT /api/users/{id}/role","GET /api/exports",...],\n'
            '    "trust_boundaries": ["multi-tenant org isolation","user-vs-admin", ...],\n'
            '    "risk": "High|Medium|Low"\n'
            "  }\n"
            "Be concrete about sensitive_actions and key_objects (use real paths you observed) — the access "
            "and fuzzer agents test exactly these. Leave a list empty rather than guessing.")

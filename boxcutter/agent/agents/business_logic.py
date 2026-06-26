"""Business-logic - abuses the application's rules and workflows, not its parsers."""

from ..base import Agent


class BusinessLogic(Agent):
    name = "business-logic"
    tools = {"http-request", "fuzz", "browser-actions"}
    max_steps = 20

    def should_run(self, ctx):
        s = ctx.surface
        return bool(s.get("endpoints") or s.get("param_urls") or s.get("tier1") or ctx.identities)

    def objective(self, ctx):
        return (
            "You are BUSINESS-LOGIC - abuse the application's RULES and WORKFLOWS, the class scanners cannot find. "
            "Ground every test in the APP PROFILE (key_objects, sensitive_actions, workflows) and use the strongest "
            "identity. Form a hypothesis from the logic, then prove it with ONE well-formed `http-request` - do not "
            "blind-fuzz:\n"
            "- VALUE tampering: negative / zero / overflow / fractional amount, price or quantity override, "
            "currency / discount / coupon fields, a client-supplied total - all should be rejected server-side.\n"
            "- STATE / WORKFLOW: skip a step (call a later-stage endpoint directly, e.g. /confirm without /pay), "
            "replay a one-time action, or act on an object in the wrong state (cancel an already-shipped order).\n"
            "- MASS-ASSIGNMENT: add an unexpected privileged field (role / isAdmin / owner_id / status / verified) "
            "to a create or update body and check whether it sticks.\n"
            "- TENANCY: swap a tenant / org id to act across the boundary.\n"
            "- PARAM POLLUTION / type juggling on logic parameters.\n"
            "Each accepted abuse is a finding - quote the response field that proves the rule was bypassed, with the "
            "exact reproduce (including the identity header). Hand candidates to the validator unconfirmed.\n"
            "Clever: chain state out of order (call step B without A; reuse a one-time token); abuse numeric edges "
            "(0, negative, 1e9, 0.001, scientific notation) and client-sent price/total/role/quantity; stack a "
            "coupon/param by repeating it; and act on an object in a state that should forbid it.")

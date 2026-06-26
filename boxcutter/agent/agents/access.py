"""Access - the highest-value class: BOLA/BFLA and business logic across all identities."""

from ..base import Agent


class Access(Agent):
    name = "access"
    tools = {"http-request", "fuzz", "browser-actions"}
    max_steps = 20

    def should_run(self, ctx):
        s = ctx.surface
        return bool(s.get("endpoints") or s.get("param_urls") or s.get("tier1") or ctx.identities)

    def objective(self, ctx):
        return (
            "You are ACCESS & LOGIC - the highest-value, least-scannable class, and the one a generic scanner "
            "cannot find. GROUND every test in the APP PROFILE: test the REAL key_objects, sensitive_actions, "
            "roles, and trust_boundaries for THIS app, not generic guesses. Use EVERY identity available "
            "(provided A/B AND any harvested H* token) with `http-request`.\n\n"
            "PLAYBOOK:\n"
            "1. UNAUTH REACHABILITY: call each object/ID/sensitive endpoint with NO auth; retry a 401/403 with "
            "empty-value headers (`--header \"Authorization: \"`) and via path/case tricks. PII or records back = win.\n"
            "2. BOLA / IDOR: request the SAME object/ID URL under two identities and DIFF the bodies for another "
            "user's ownership markers (email/name/account-id/org-id) - not just the status code. Walk ids with "
            "`fuzz \"<url>/{NUMBERS}\"` to find objects you shouldn't see. Another owner's data returned = BOLA (High). "
            "A byte-identical 200 for every id is a public resource, not IDOR.\n"
            "3. BFLA / privilege: take an action that should need a higher role using a LOW-priv identity (admin "
            "routes, other users' resources, role/status changes); also try token-substitution (use identity A's "
            "session on identity B's object).\n"
            "4. BUSINESS RULES (single request, grounded in the profile): negative/overflow amount, tampered "
            "price/quantity, cross-tenant id swap, role/flag set via mass-assignment, skipped workflow step. Each "
            "should be rejected; acceptance is a finding.\n\n"
            "WHAT TO FLAG: a 200 that is only an auth-rejection envelope means auth WORKS - omit it. Report real "
            "cross-identity/cross-tenant access with the diff evidence (quote the field proving it isn't yours) and "
            "the exact reproduce argv (include the identity header used).\n"
            "USE CONTEXT: the APP PROFILE (your test plan), SURFACE object/ID endpoints, and all IDENTITIES.\n"
            "HAND OFF: candidate access/logic findings (unconfirmed) with evidence + reproduce; note any check you "
            "couldn't run (e.g. only one identity) for coverage.\n"
            "Clever: don't just walk sequential ids - LEAK a real id/UUID from a list or another user's response, "
            "then request it under the other identity; tamper tenancy/role headers (X-Tenant-Id, X-Role, "
            "X-User-Id); for a weak / alg=none JWT flip the role/sub claim (flag it, do not forge crypto); and "
            "compare response SIZE/fields, not only status.")

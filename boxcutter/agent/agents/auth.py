"""Auth - establishes and validates the shared session(s) every later agent reuses."""

from ..base import Agent


class Auth(Agent):
    name = "auth"
    tools = {"http-request"}
    max_steps = 8

    def objective(self, ctx):
        return (
            "You are AUTH. You own the SHARED SESSION: every later agent tests with the identities you confirm, "
            "so validate them once, here, and figure out HOW this app authenticates (so harvested creds can be "
            "applied the same way later).\n\n"
            "PLAYBOOK:\n"
            "1. For each identity in IDENTITIES (and any harvested H* token), `http-request <base or an authed "
            "endpoint> --header ...` and compare to the SAME request with NO auth. A 200 carrying user context "
            "(name/email/account) = live; a 401, or a redirect to /login, or an identical-to-anonymous body = dead.\n"
            "2. Pick a stable AUTHED LIVENESS endpoint (e.g. /api/me, /account, /dashboard) the later agents can "
            "use to tell 'auth still works' from 'real finding'.\n"
            "3. Determine the auth MECHANISM and relative privilege: Bearer JWT vs Cookie session vs api-key; and "
            "which identity is higher-privileged (A vs B) - access/lateral need this for BFLA.\n\n"
            "WHAT TO FLAG: a dead/expired session NOW (so downstream doesn't waste calls); auth that is missing "
            "entirely on a sensitive endpoint is a finding, not just 'no auth'.\n"
            "USE CONTEXT: the provided IDENTITIES and BASE url.\n"
            "HAND OFF: in artifacts.notes - which identities are live, which is higher-priv, the auth mechanism, "
            "and the liveness endpoint. Only echo a token under artifacts.tokens if you CONFIRMED it authenticates. "
            "If no auth was provided, say 'unauthenticated' and continue - the run still proceeds anonymously.")

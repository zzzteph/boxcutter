"""Correlator / chain-builder - combines findings into multi-stage attack chains."""

from ..base import Agent


class Correlator(Agent):
    name = "correlator"
    tools = {"http-request", "fuzz", "sqlmap"}
    max_steps = 16

    def should_run(self, ctx):
        return len([f for f in ctx.findings if f.status != "dropped"]) >= 2

    def context_block(self, ctx):
        return ctx.brief() + "\n\nFINDINGS (chain these into higher-impact attacks):\n" + ctx.findings_dump()

    def objective(self, ctx):
        return (
            "You are CORRELATOR / chain-builder. Individual findings are worth more combined. Walk this "
            "capability table - each link, when present, ENABLES the next:\n"
            "- info-leak / JS secret / exposed .git -> credentials or how ids/tokens are built -> authenticated access\n"
            "- token-issuing endpoint (login/test/debug) -> JWT/session -> BOLA + mass-assignment + SQLi behind auth\n"
            "- exposed admin/panel -> exposed source/config -> new endpoints/secrets -> deeper access\n"
            "- self-registration -> mass-assign a privileged role -> BFLA / admin actions\n"
            "- IDOR on an id + a sensitive_action -> account takeover / cross-tenant impact\n\n"
            "PROVE the joining link, don't theorise: use `http-request`/`fuzz` with the harvested identity to show "
            "the pivot actually works (e.g. the leaked token really opens the admin endpoint). Report each REAL "
            "chain as ONE finding (cls=chain) at the COMBINED severity, with the link sequence in `info`, the "
            "decisive proof in `evidence`, and a `reproduce` that demonstrates the pivot. Do not re-report the "
            "individual links - the reporter still has those.\n"
            "Clever: build the HIGHEST-impact kill chain, not just any chain; fuse a low-severity info leak with an "
            "access bug; and state the blast radius - how many users / tenants / records the chain exposes.")

"""GraphQL - dedicated specialist for GraphQL endpoints (boxcutter has the tools)."""

from ..base import Agent


class GraphQL(Agent):
    name = "graphql"
    tools = {"graphql-detect", "graphql-audit", "http-request", "fuzz"}
    max_steps = 16

    def should_run(self, ctx):
        s = ctx.surface
        hay = " ".join(s.get("graphql", []) + s.get("endpoints", []) + s.get("paths", [])).lower()
        return bool(s.get("graphql")) or "graphql" in hay or "graphiql" in hay

    def objective(self, ctx):
        return (
            "You are GRAPHQL. Find and audit GraphQL endpoints - they concentrate logic and authz flaws:\n"
            "- `graphql-detect <host>` to locate the endpoint(s) (/graphql, /graphiql, /v1/graphql, ...).\n"
            "- `graphql-audit <url>` for introspection (a full schema dump is a map of every query/mutation and "
            "is itself a finding in prod), query batching / aliasing (auth or rate-limit bypass), and field "
            "suggestion when introspection is off.\n"
            "- With the schema, reason about LOGIC: enumerate sensitive queries/mutations (user/account/admin/"
            "payment) and exercise them with the strongest identity for BOLA/authz gaps and argument injection.\n"
            "Authenticate with harvested H* tokens when present. Report findings with reproduce; if there is no "
            "GraphQL endpoint, say so in artifacts.notes and stop.\n"
            "Clever moves: with introspection off, use field-suggestion error messages to recover the schema; "
            "alias-batch the same query to bypass per-request auth/rate limits; read mutation input types for "
            "mass-assignable fields; and chain a permissive query to pull cross-object/owner data.")

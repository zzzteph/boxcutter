"""API - drives documented APIs; the agent that most often starts a credential chain."""

from ..base import Agent


class Api(Agent):
    name = "api"
    tools = {"swagger-specs", "swagger-parser", "swagger-endpoints", "graphql-detect",
             "graphql-audit", "fuzz", "http-request"}
    max_steps = 22

    def should_run(self, ctx):
        s = ctx.surface
        hay = " ".join(s.get("endpoints", []) + s.get("paths", [])).lower()
        return any(s.get(k) for k in ("api", "spec", "graphql", "endpoints")) or \
            any(t in hay for t in ("/api", "swagger", "openapi", "/v1", "/v2", "graphql", ".json"))

    def objective(self, ctx):
        return (
            "You are API. Documented APIs are where the best chains start - a single test/login endpoint can hand "
            "you a token that unlocks everything. If SURFACE has a spec, /api, or GraphQL, drive it hard. If there "
            "is genuinely no API surface, say so in artifacts.notes and stop.\n\n"
            "PLAYBOOK (REST/OpenAPI):\n"
            "1. `swagger-specs <host>` to find spec URLs; `swagger-parser <spec>` to understand it; "
            "`swagger-endpoints <spec> --fuzzable` to get {FUZZ}-marked endpoint variants.\n"
            "2. `http-request` each documented endpoint - first with NO auth, then with each identity. A declared "
            "security scheme is NOT proof it's enforced: an endpoint that returns data unauthenticated is a finding.\n"
            "3. CREDENTIAL HUNT: watch every response (especially login/token/auth/test/debug/register endpoints) "
            "for a JWT or api key. If you get one, IMMEDIATELY reuse it as `--header \"Authorization: Bearer ...\"` "
            "on the other endpoints AND report it under artifacts.tokens - this is the chain.\n"
            "4. Per object/collection endpoint, probe BOLA (same id under two identities, diff the bodies), "
            "mass-assignment (POST/PUT an extra privileged field like role/isAdmin/owner_id), and `fuzz` it for "
            "injection.\n\n"
            "PLAYBOOK (GraphQL): `graphql-detect <host>` to locate it, then `graphql-audit <url>` for introspection "
            "(schema leak), query batching, and field-suggestion - introspection enabled in prod is a finding and a "
            "map of every sensitive_action.\n\n"
            "USE CONTEXT: SURFACE.api/spec/graphql/endpoints, the identities, and the APP PROFILE's sensitive_actions.\n"
            "HAND OFF: any harvested token in artifacts.tokens; every documented endpoint you confirmed in "
            "artifacts.endpoints (so lateral re-sweeps them with the token); findings with reproduce argv.\n"
            "Clever moves: probe UNDOCUMENTED siblings of documented routes (/v1 vs /v2, /internal/*, "
            "singular/plural); swap the HTTP method (a GET-only doc endpoint may still accept POST/PUT); send a "
            "JSON endpoint a form body (parser confusion); push limit/page/fields to extremes for over-fetch; and "
            "add admin-ish fields (role/isAdmin/owner_id) to a write body for mass-assignment.")

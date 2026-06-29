"""graphql executor - an agent that tests a GraphQL endpoint (introspection, hidden mutations, IDOR)."""

from __future__ import annotations

from .base import Executor


class GraphQL(Executor):
    name = "graphql"
    description = "Test GraphQL: introspection, hidden/privileged mutations, IDOR, secret fields, batching."
    tools = {"graphql-detect", "graphql-audit", "http-request"}
    max_steps = 10
    objective = (
        "You are the GRAPHQL agent. Locate the endpoint (graphql-detect) and audit it (graphql-audit):\n"
        "- run introspection to map every query/mutation; invoke the HIDDEN/privileged ones the UI never calls "
        "(deleteUser, makeAdmin, a `secret` field that leaks keys).\n"
        "- test object-id arguments for IDOR (read another owner's record).\n"
        "- alias-BATCH a guarded resolver (`a:op(..) b:op(..)`) to bypass per-request rate-limit/auth.\n"
        "Quote leaked data / secret fields (redacted) as evidence.")

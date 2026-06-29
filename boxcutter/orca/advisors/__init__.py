"""Advisor roster - AGNOSTIC observers ORCA consults each cycle. Each is ONE trust-boundary invariant
applied uniformly across the whole surface (not one-advisor-per-bug)."""

from __future__ import annotations

from .observers import (
    ReconAdvisor, CoverageAdvisor, AuthzDiffAdvisor, MutationAdvisor, ReflectionAdvisor,
    WorkflowAdvisor, GraphQLAdvisor, ExposureAdvisor, ChainAdvisor,
)

ADVISORS = [
    ReconAdvisor(),         # foundation: map the surface first
    CoverageAdvisor(),      # every discovered endpoint is exercised - no sampling
    AuthzDiffAdvisor(),     # a response must depend on the caller (BOLA/unauth/privesc) + identity gate
    MutationAdvisor(),      # every client value re-validated server-side (IDOR/price-logic/tamper/traversal)
    ReflectionAdvisor(),    # controlled input must not become executable output (reflected + stored XSS)
    WorkflowAdvisor(),      # every auth/state step enforced, in order (forgery/step-skip/response-trust)
    GraphQLAdvisor(),       # GraphQL introspection + hidden mutations + object-level authz
    ExposureAdvisor(),      # internal artifacts must not be reachable
    ChainAdvisor(),         # escalate every confirmed finding to impact
]


def gather(state) -> list:
    """All advisors' suggestions for the current state, highest priority (1) first."""
    out = []
    for adv in ADVISORS:
        try:
            out += adv.suggest(state)
        except Exception:  # noqa: BLE001 - a broken advisor must not stop the run
            continue
    return sorted(out, key=lambda s: s.priority)

"""authn executor - an agent that tests authentication (token forgery, weak/predictable tokens, reset)."""

from __future__ import annotations

from .base import Executor


class Authn(Executor):
    name = "auth"
    description = "Test authentication: token forgery/predictability, JWT flaws, broken reset, default creds."
    tools = {"http-request", "fuzz"}
    max_steps = 12
    objective = (
        "You are the AUTH/WORKFLOW agent. Test how the app proves identity AND whether each step of a multi-step "
        "flow is enforced server-side and in order:\n"
        "- inspect the session/JWT: decode base64(JSON) claims; if the token is predictable/forgeable (e.g. the "
        "token IS the user id, or alg=none, RS256->HS256 key-confusion, weak HMAC secret) set role/user to admin "
        "and replay it.\n"
        "- broken password reset: request a reset and check if the token is returned in the response, predictable, "
        "or never verified.\n"
        "- STEP-SKIP: in a login/2fa/oauth/checkout/payment flow, call the FINAL step directly (post-2fa, "
        "post-payment, confirm/activate) without completing the prior step - if it succeeds, the step is "
        "client-enforced only.\n"
        "- RESPONSE-TRUST: where the client sends back a server response (a success=true/role/verified/paid field, "
        "or a re-submitted result), flip it and replay - if the app trusts it, that's account-takeover / "
        "payment-bypass class.\n"
        "- default/guessable credentials at the login endpoint (FLAG it; do not brute-force).\n"
        "- if your task asks you to MINT an identity, register or log in a fresh second account so authorization "
        "diffing has two distinct identities.\n"
        "After any successful auth, put the resulting Set-Cookie/token in artifacts.tokens as a new identity. "
        "Quote the forged/leaked/flipped token or field (redacted) as evidence.")

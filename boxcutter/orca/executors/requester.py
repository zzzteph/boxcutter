"""access executor - an agent that tests authorization: IDOR/BOLA, BFLA, excessive-data, across identities."""

from __future__ import annotations

from .base import Executor


class Requester(Executor):
    name = "request"
    description = "Request-tampering battery: authz (IDOR/BOLA, BFLA) + value-logic across identities. args: {url, id}."
    tools = {"http-request", "fuzz"}
    max_steps = 14
    objective = (
        "You are the REQUEST-TAMPERING agent - the highest-value class. Replay each request with ONE thing changed "
        "and DIFF the response against the honest baseline. For the endpoint(s) in your task:\n"
        "- UNAUTH reach: request with NO auth; PII/records back = a finding.\n"
        "- BOLA/IDOR: request the SAME object under EACH identity and DIFF the bodies - another owner's data "
        "(email/account-id/owner) returned = High. If your task hands you a leaked id/UUID, request THAT object "
        "under your identity. Walk numeric ids with `fuzz \"<url>/{NUMBERS}\"`; try '../' on path ids for "
        "secondary-context IDOR.\n"
        "- VALUE-LOGIC (do not skip): for any amount/price/quantity/total/discount/coupon/modifier field, replay "
        "with it NEGATED, ZEROED, INFLATED, or the key DUPLICATED, then RE-READ the server-computed total/price. If "
        "the total drops, goes <=0, or the duplicate is honored, the server trusts client math = High. The client "
        "never owns the price.\n"
        "- BFLA/privesc + mass-assignment: reach an admin-only action as a low-priv identity; add role/isAdmin/owner "
        "to a write body.\n"
        "- EXCESSIVE DATA: flag passwords/secrets/PII/full card numbers in any response.\n"
        "Quote the field that proves the tamper worked. A byte-identical 200 for every id is public, not IDOR - "
        "don't report it.")

"""The advisor roster - AGNOSTIC observers that SUGGEST what to test.

Each advisor encodes ONE general trust-boundary invariant and applies it UNIFORMLY across the whole
surface. It never matches on a vendor string or a single bug title - the PRINCIPLE is the unit, so the
same advisor that catches a courier IDOR catches a restaurant price-tamper. The roster:

  - coverage:    every discovered endpoint is exercised at least once          (no sampling)
  - authz-diff:  a response must DEPEND ON THE CALLER                          (BOLA / unauth / privesc)
  - mutation:    every client value is re-validated server-side                (IDOR / price-logic / tamper / traversal)
  - reflection:  attacker input must not become executable output             (reflected + stored XSS)
  - workflow:    every step of an auth/state flow is enforced, in order        (token forgery / step-skip / response-trust)
  - chain:       every confirmed finding is escalated to real impact
  - exposure:    internal artifacts must not be reachable
  - graphql:     the GraphQL surface is introspected and abused

Advisors only PROPOSE - ORCA (the LLM planner) reads all suggestions and decides which executor runs.
The executor agents hold the "how to test"; advisors enumerate the agnostic "what must be tested".
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..state import Suggestion
from .base import Advisor

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_INT_SEG = re.compile(r"/(\d{2,})(?=/|$)")
# value-name hints mark a parameter's INTENT; the value SHAPE still decides the concrete mutation.
_AMOUNT_KEY = ("amount", "price", "total", "qty", "quantity", "count", "cost", "sum", "balance",
               "credit", "discount", "coupon", "fee", "points", "value", "tip", "modifier", "subtotal")
_ID_KEY = ("id", "uuid", "user", "account", "order", "customer", "courier", "restaurant", "email",
           "ref", "owner", "profile", "address", "invoice", "token")
_FLOW_HINT = ("login", "logout", "auth", "token", "session", "register", "signup", "reset", "forgot",
              "verify", "otp", "2fa", "mfa", "oauth", "sso", "callback", "confirm", "activate",
              "checkout", "payment", "/pay", "redeem")


# -- shape-driven helpers (target-independent; this is what makes the advisors agnostic) ----------

def _ran(state, action) -> bool:
    return any(p["status"] == "run" and p["action"].startswith(f"run {action} ") for p in state.plan)


def _shape(v: str) -> str:
    v = (v or "").strip()
    if _UUID.fullmatch(v):
        return "uuid"
    if re.fullmatch(r"-?\d+", v):
        return "int"
    if re.fullmatch(r"-?\d+\.\d+", v):
        return "num"
    if "@" in v and "." in v.rsplit("@", 1)[-1]:
        return "email"
    return "str"


def _query_params(url: str):
    try:
        return parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return []


def _path_ids(url: str):
    try:
        path = urlsplit(url).path
    except ValueError:
        return []
    return _UUID.findall(path) + _INT_SEG.findall(path)


def _id_params(url: str):
    return [k for k, v in _query_params(url)
            if k.lower() in _ID_KEY or k.lower().endswith("id") or _shape(v) in ("uuid", "int", "email")]


def _amount_params(url: str):
    return [k for k, v in _query_params(url) if k.lower() in _AMOUNT_KEY or _shape(v) in ("int", "num")]


def _leaked_ids(state):
    found = []
    for out in list(state.responses.values())[-30:]:
        found += _UUID.findall(out or "")
    return sorted(set(found))


def _reflected_params(state):
    """Params whose VALUE shows up verbatim in a recorded response - the 'controlled-in -> appears-out' signal."""
    bodies = " ".join(str(v) for v in list(state.responses.values())[-40:])
    out = []
    if not bodies:
        return out
    for url in state.all_endpoints():
        for k, v in _query_params(url):
            if v and len(v) >= 4 and v in bodies:
                out.append((url, k))
    return out


# -- the roster -----------------------------------------------------------------------------------

class ReconAdvisor(Advisor):
    """Foundation: you cannot test a surface you haven't mapped."""
    name = "recon-advisor"

    def suggest(self, state):
        if not state.all_endpoints():
            return [Suggestion("recon", {"target": state.base_url},
                               "surface is empty - map it before testing", 1, self.name)]
        return []


class CoverageAdvisor(Advisor):
    """Invariant: every documented/discovered endpoint is exercised at least once - no sampling."""
    name = "coverage-advisor"

    def suggest(self, state):
        untested = state.untested_endpoints()
        if not untested:
            return []
        out = [Suggestion("fuzz", {"sweep": True},
                          f"{len(untested)} endpoint(s) never fuzzed - injection battery", 2, self.name)]
        for url in untested[:8]:
            out.append(Suggestion("request", {"url": url},
                                  "endpoint never request-probed - authz + excessive-data check", 3, self.name))
        return out


class AuthzDiffAdvisor(Advisor):
    """Invariant: a response must DEPEND ON THE CALLER. Replay every id-bearing endpoint across each
    identity + no-auth (+ any leaked id) and DIFF. One principle for IDOR/BOLA/unauth/privesc, keyed on
    'does the answer change when the asker changes' - never on URL keywords. Also enforces the identity
    gate: cross-tenant access cannot be PROVEN with fewer than two identities."""
    name = "authz-diff-advisor"

    def suggest(self, state):
        out = []
        id_eps = [u for u in state.all_endpoints() if _path_ids(u) or _id_params(u)]
        if id_eps and len(state.identities) < 2 and not _ran(state, "auth"):
            out.append(Suggestion("auth", {"mint_identity": True},
                                  "id-bearing endpoints exist but <2 identities - register/login a 2nd account to "
                                  "prove cross-tenant access", 1, self.name))
        leaked = _leaked_ids(state)
        for url in id_eps[:8]:
            args = {"url": url}
            if leaked:
                args["id"] = leaked[0]
            out.append(Suggestion("request", args,
                                  "replay under EACH identity + no-auth (and any leaked id) and DIFF - an identical "
                                  "answer for every caller, or another owner's data, = broken authorization",
                                  2, self.name))
        return out


class MutationAdvisor(Advisor):
    """Invariant: EVERY value the client can set must be re-validated server-side. For each observed
    parameter, propose the mutation its SHAPE invites - amount->negate/zero/inflate/duplicate,
    id->swap/enumerate/traverse, anything->inject. Folds IDOR, price/quantity logic, parameter tampering
    and secondary-context traversal into one shape-driven principle that carries to any target."""
    name = "mutation-advisor"

    def suggest(self, state):
        out = []
        seen = 0
        for url in state.all_endpoints():
            if not _query_params(url):
                continue
            amounts = sorted(set(_amount_params(url)))
            ids = sorted(set(_id_params(url)))
            if amounts:
                out.append(Suggestion("request", {"url": url},
                                      f"value-logic: negate/zero/inflate/duplicate {','.join(amounts[:4])}, then re-read "
                                      "the computed total/price - the server (not the client) must own the math",
                                      2, self.name))
            if ids:
                out.append(Suggestion("request", {"url": url},
                                      f"id-tamper: swap/enumerate {','.join(ids[:4])} across identities; try '../' on any "
                                      "path id (secondary-context IDOR)", 2, self.name))
            seen += 1
            if seen >= 6:
                break
        return out


class ReflectionAdvisor(Advisor):
    """Invariant: attacker-controlled input must never come back as executable output. Where a parameter
    value is reflected in a response, confirm reflected XSS; if the value persists, inject a tagged marker
    then RE-FETCH the rendering view for STORED XSS. Keyed on 'controlled-in -> appears-out'."""
    name = "reflection-advisor"

    def suggest(self, state):
        out = []
        for url, key in _reflected_params(state)[:6]:
            out.append(Suggestion("fuzz", {"url": url},
                                  f"'{key}' is reflected verbatim - confirm reflected XSS; if it persists, inject a "
                                  "uniquely tagged marker and RE-FETCH the read view for STORED XSS", 2, self.name))
        return out


class WorkflowAdvisor(Advisor):
    """Invariant: every step of an auth/state workflow must be enforced server-side AND in order. Where a
    login/reset/2fa/oauth/checkout/payment flow exists, test forgeable/predictable tokens, broken reset,
    STEP-SKIPPING (reach the post-2fa / post-payment state directly) and RESPONSE-TRUST (flip a
    client-visible success/role field). Generalizes auth into 'can a step be skipped or its result forged'."""
    name = "workflow-advisor"

    def suggest(self, state):
        hay = " ".join(state.all_endpoints()).lower()
        if (state.identities or any(h in hay for h in _FLOW_HINT)) and not _ran(state, "auth"):
            return [Suggestion("auth", {},
                               "test the auth/state workflow: token forgery/reset, STEP-SKIP (jump straight to the "
                               "post-2fa / post-payment state), RESPONSE-TRUST (flip a success/role field the client "
                               "sends back)", 2, self.name)]
        return []


class GraphQLAdvisor(Advisor):
    """Invariant: a GraphQL surface must not expose introspection, hidden mutations, or unscoped objects."""
    name = "graphql-advisor"

    def suggest(self, state):
        hay = " ".join(state.surface.get("graphql", []) + state.all_endpoints()).lower()
        if ("graphql" in hay or state.surface.get("graphql")) and not _ran(state, "graphql"):
            return [Suggestion("graphql", {}, "GraphQL detected - introspection + hidden mutations + object-level authz",
                               2, self.name)]
        return []


class ExposureAdvisor(Advisor):
    """Invariant: internal artifacts (VCS/config/secrets/panels/debug endpoints) must not be reachable."""
    name = "exposure-advisor"

    def suggest(self, state):
        if not any(e["tool"] == "nuclei" for e in state.ledger) and not _ran(state, "exposure"):
            return [Suggestion("exposure", {}, "no exposure scan yet - VCS/config/secrets/panels/test-endpoints",
                               3, self.name)]
        return []


class ChainAdvisor(Advisor):
    """Invariant: every confirmed finding is escalated to its maximal, concrete impact."""
    name = "chain-advisor"

    def suggest(self, state):
        out = []
        for f in state.findings:
            if f.status == "dropped":
                continue
            if f.cls == "sqli" and f.status != "confirmed":
                out.append(Suggestion("sqlmap", {"url": f.url}, f"confirm+extract the SQLi at {f.url}", 1, self.name))
            elif f.cls in ("lfi", "rce"):
                out.append(Suggestion("sqlmap", {"url": f.url},
                                      f"exploit the {f.cls} at {f.url} (read source/extract)", 1, self.name))
            elif f.cls == "exposure" and any(t in f.url for t in (".git", "/config", ".env", "heapdump")):
                out.append(Suggestion("exposure", {"dir": f.url.rsplit("/", 1)[0]},
                                      "mine the exposed source/config dir", 2, self.name))
            elif f.cls in ("secret", "jwt"):
                out.append(Suggestion("auth", {}, "harvested secret/token - test forgery + reuse", 2, self.name))
            elif f.cls in ("bola", "idor"):
                out.append(Suggestion("request", {"url": f.url},
                                      "broken authz confirmed - enumerate the full object range for blast radius",
                                      2, self.name))
        return out

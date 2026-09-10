---
name: jwt
label: JWT attacks (alg:none, key confusion, weak secret, claim tampering)
triggers: [jwt-token, bearer-auth, set-cookie-jwt, eyJ-string, session-token]
preconditions: [a JWT handed to you in a cookie, body, Authorization header, or param]
scope: requests-only
safety: benign
severity_hint: critical
---

# JWT attacks

## Overview
A JSON Web Token (`eyJ...`) carries the caller's identity and claims, signed by the server. The bug is that the
server trusts a token it should have rejected: an unsigned token, one signed with a key you control, one whose
signature it never checks, or one whose claims you tampered. Proof is never "the token decodes" - it is a token
YOU forged that returns the victim's/admin's data at an endpoint where the original (or an `alg:none`) token is
refused. That is always a differential: forged token succeeds, control is denied.

## Attack surface
- Transport: `Set-Cookie`, response body, `Authorization: Bearer eyJ...`, a query/body param.
- Header: `alg` (none / HS256 / RS256), `kid` (may be a file path or SQL sink), `jku`/`x5u` (remote key URL).
- Payload claims: `role`, `isAdmin`, `sub`, `user_id`, `tenant`, `email`, `exp` - the escalation levers.

## Hunt methodology
1. Capture a token and decode header + payload (base64url) with `http-request`-driven analysis. Note `alg`,
   `kid`, and every claim that names identity or privilege.
2. Establish a control: the endpoint's response to the ORIGINAL token vs to a stripped/`alg:none` token, so the
   harness has a denied baseline to compare a forged token against.
3. Attack the signature (alg:none, key confusion, weak-secret crack, unverified-sig, kid injection), then
   replay the forged token and compare to control.
4. Tamper claims (`role`/`isAdmin`/`sub`/`tenant`) for horizontal/vertical escalation, then CHAIN a working
   forge -> victim data / admin console / account takeover.

## Checks (predict -> send -> assert)
- technique: alg:none forgery
  send: set header `"alg":"none"`, drop the signature, keep/raise your claims, replay to a gated endpoint
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403]}
  fp_note: control = the same request with a random/invalid token (must be denied). A 200 that returns a
           generic/login page is not acceptance - the body must be the gated/victim resource.

- technique: weak-secret forge (HS256)
  send: crack the HS256 secret (common words, `secret`/`changeme`/`jwt`, domain labels, product name), mint a
        token with an elevated claim, replay it
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403]}
  fp_note: only a secret that actually verifies proves the crack; if the forged token is refused the secret is
           wrong, not the vuln absent.

- technique: RS256 -> HS256 key confusion
  send: re-sign an RS256 token with HS256 using the server's PUBLIC key bytes as the HMAC secret, replay it
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403]}
  fp_note: needs the real public key (from `/jwks`, a cert, or the response); a guessed key that fails to
           verify is not a finding.

- technique: unverified-signature / claim tampering
  send: change one claim (`role`/`isAdmin`/`sub`) and resend with the ORIGINAL signature untouched
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403]}
  fp_note: if the server verifies, the tampered token is rejected; acceptance means the signature is never
           checked. Confirm the response reflects the tampered identity, not your own.

## Notes
Severity: critical when a forge grants admin or another user's account (auth bypass / ATO); high for a limited
horizontal escalation. Evidence = the forged token, the endpoint's response to it, and the denied control
response - cite all three. A working forge is the START: chain it to the data or console it unlocks.

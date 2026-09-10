---
name: auth
label: Authentication & session soundness
triggers: [login, signin, oauth, session-cookie, set-cookie, 401, password-reset, mfa, remember-me]
preconditions: [the app has authentication - a login form, a session cookie, a 401/403, or an auth endpoint]
scope: requests-only
safety: benign
severity_hint: high
---

# Authentication & session soundness

## Overview
Authentication is sound only if a session cannot be stolen, replayed, fixed, forged, or bypassed, and recovery
flows cannot be turned against a user. Get a real session first, then test each guarantee by making the server
accept something it should refuse: an old cookie after logout, a fixed id that survives login, a gated page with
no session, a reset token that leaks or reuses. Prove differentially - the weak behaviour vs a clean control.

## Attack surface
- Login/session: `/login`, `/signin`, `/oauth`, `/session`; the `Set-Cookie` session token and its flags.
- Recovery: password-reset request/confirm, `Host`/`X-Forwarded-Host` in reset-link generation, remember-me tokens.
- Step-up: MFA/OTP endpoints and the post-step-1 continuation.
- Enumeration surfaces: login, registration, and reset responses that differ for real vs fake accounts.

## Hunt methodology
1. Obtain a session with `http-request` (log in if creds are available), and crawl the authenticated surface with
   `katana-crawl` under that session so gated endpoints are discovered. Two accounts unlock cross-account tests.
2. Inspect the session cookie's flags and the token's shape (entropy, structure) - JWT specifics: see the JWT play.
3. Exercise each guarantee: logout-then-replay, fix-then-login, forced-browse with no session, reset-flow abuse.
4. Keep it benign: never brute-force or spray real credentials (locks accounts, usually out of scope); prove reset
   flaws against your OWN account; read, don't hijack.

## Checks (predict -> send -> assert)
- technique: session survives logout
  send: log in, log out, then replay the OLD session cookie on a gated endpoint
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403]}
  fp_note: control = the same endpoint hit with no/invalidated session; the old cookie must still return YOUR
           gated data, proving the server did not invalidate it.

- technique: session fixation
  send: set a known session id before login; complete login; check whether the id changed
  predict: {header_contains: "<the pre-login session id>"}   # id NOT rotated on auth
  refute_if: {header_contains: "Set-Cookie"}                 # a fresh id was issued at login
  fp_note: only a fixation if the SAME pre-set id remains valid post-login; a rotated id in Set-Cookie refutes it.

- technique: forced browsing (missing authN)
  send: request a post-auth page/API with NO session
  predict: {status_in: [200], body_contains: "<a field only an authed user sees>"}
  refute_if: {status_in: [401, 403]}
  fp_note: a login page or soft-404 returned with 200 is not access - the body must be the real gated content.

- technique: weak cookie flags
  send: read the login `Set-Cookie` response header
  predict: {header_contains: "Set-Cookie", body_not_contains: "HttpOnly"}   # inspect for missing HttpOnly/Secure/SameSite
  refute_if: {header_contains: "HttpOnly"}
  fp_note: header_contains matches on the Set-Cookie line; missing HttpOnly = JS-stealable (chains with XSS),
           missing Secure = sent over plaintext. Note each missing flag rather than treating one 200 as the finding.

- technique: password-reset token leak / poisoning
  send: trigger a reset; inspect if the token is RETURNED in the response, or poison the link via `X-Forwarded-Host`
  predict: {body_contains: "<the reset token>", header_contains: "boxcutter.evil"}
  refute_if: {body_not_contains: "token"}
  fp_note: prove on your own account - a token in the response body, or a reset link built from the injected Host,
           is the finding; a token delivered only out-of-band (email) is not gradeable here (open_proof_gap).

- technique: user enumeration
  send: submit login/reset for a KNOWN-good vs a KNOWN-bad username
  predict: {differs_from_control: true}   # control = the known-bad response
  refute_if: {differs_from_control: false}
  fp_note: the difference must be stable and meaningful (message text, status, or latency), not a nonce/CSRF
           token; re-fire both to rule out jitter.

- technique: MFA / step-up bypass
  send: after completing step 1, call the post-MFA endpoint without completing step 2
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403]}
  fp_note: the finding is reaching the authenticated surface with MFA incomplete; OTP brute-force/reuse is a
           separate rate-limit test - do not spray codes without authorization.

## Notes
Severity: high for a replayable/fixable session or a reset flaw reaching account takeover; critical if it yields
admin or scales across users; medium for enumeration/weak flags alone (they chain upward). Evidence for each check
is the paired exchange - the weak behaviour and the denied control. A confirmed weakness is a step toward takeover:
note what it chains to, and never brute-force real credentials.

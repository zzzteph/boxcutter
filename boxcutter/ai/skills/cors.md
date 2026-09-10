---
name: cors
label: CORS misconfiguration (origin reflection with credentials)
triggers: [access-control-allow-origin, cross-origin-api, browser-read-json, cors-header]
preconditions: [an endpoint that returns an Access-Control-Allow-Origin header]
scope: requests-only
safety: benign
severity_hint: high
---

# CORS misconfiguration

## Overview
An API returns `Access-Control-Allow-Origin` and gets the trust boundary wrong: it reflects an attacker-supplied
`Origin` (or accepts `null`) AND sets `Access-Control-Allow-Credentials: true`. That combination lets any
malicious page read this user's authenticated responses cross-origin. Proof is entirely in the response headers -
you send a crafted `Origin` and assert what comes back. Reflection WITHOUT credentials only matters for data that
needs no session.

## Attack surface
- Any endpoint returning `Access-Control-Allow-Origin` - JSON APIs read from the browser, cross-origin apps.
- Credentialed endpoints (session cookie or auth header) are the high-value case; those are the responses an
  attacker page most wants to read.
- Preflight-gated routes: an `OPTIONS` that echoes `Access-Control-Allow-*` reveals the policy before the real
  request.

## Hunt methodology
1. From recon and `api-map`, list endpoints that emit `Access-Control-Allow-Origin`. `note_coverage` each.
2. Replay a request with a crafted `Origin: https://evil.example` header and inspect the response headers.
3. Test the `null` origin (`Origin: null`) - reflected + credentialed means a sandboxed iframe can exploit it.
4. Probe weak matching: `evil.com`, `target.com.evil.com`, `eviltarget.com`, `sub.target.com` - any prefix/
   suffix/substring match that reflects your origin is exploitable.
5. Always pair the origin test with a credentialed request so you can tell high (credentialed) from low.

## Checks (predict -> send -> assert)
- technique: reflected origin with credentials
  send: replay a credentialed request adding `Origin: https://evil.example`
  predict: {header_contains: "Access-Control-Allow-Origin: https://evil.example", status_in: [200]}
  refute_if: {header_contains: "Access-Control-Allow-Origin: *"}
  fp_note: a wildcard `*` is NOT the finding - browsers refuse `*` with credentials. The high finding needs the
           attacker origin reflected AND `Access-Control-Allow-Credentials: true` (assert both header_contains).

- technique: allow-credentials confirmation
  send: same crafted-origin request; inspect for the credentials header
  predict: {header_contains: "Access-Control-Allow-Credentials: true"}
  refute_if: {body_not_contains: "<a private field only a session sees>"}
  fp_note: without `Allow-Credentials: true` the reflection only exposes non-authenticated data - downgrade to
           low. Confirm the body actually holds session-scoped data worth reading cross-origin.

- technique: null origin trust
  send: replay the credentialed request with `Origin: null`
  predict: {header_contains: "Access-Control-Allow-Origin: null"}
  refute_if: {header_contains: "Access-Control-Allow-Origin: https://"}
  fp_note: `null` reflected + `Allow-Credentials: true` is exploitable from a sandboxed iframe/data URL; a
           strict origin echoed back instead means null is not trusted.

- technique: weak-match bypass
  send: `Origin: https://target.com.evil.example` (and `eviltarget.example`)
  predict: {header_contains: "Access-Control-Allow-Origin: https://target.com.evil.example"}
  refute_if: {header_contains: "Access-Control-Allow-Origin: https://target.com"}
  fp_note: the reflected value must be the attacker-controlled origin, not the legitimate one echoed unchanged.

## Notes
Severity: high when an attacker-controllable origin is reflected WITH credentials allowed on a session-scoped
endpoint (a malicious page reads the victim's authenticated data). Low when credentials are not allowed - it only
exposes public data. Evidence = the request's `Origin` and the response's `Access-Control-Allow-Origin` +
`Access-Control-Allow-Credentials` headers, cited together.

---
name: crypto
label: Cryptographic flaws (token forgery, weak/predictable secrets, ECB/IV reuse, timing, length-extension)
triggers: [jwt, session-token, signed-cookie, hmac-param, encrypted-blob, reset-token, api-signature]
preconditions: []
scope: requests-only
safety: intrusive
severity_hint: high
---

# Cryptographic flaws

## Overview
The app relies on a token, signature, or ciphertext for integrity or confidentiality, and the construction is
broken: a forgeable JWT, a guessable/weak signing secret, a mode leaking structure (ECB), a reused IV, a
non-constant-time compare, or a length-extendable MAC. Proof is behavioural - a FORGED artifact the server
accepts, or a measurable structural/timing signal. Only ever forge tokens for an identity you are entitled to test.

## Attack surface
- JWT: `alg:none`, `alg` confusion (RS256->HS256 with the public key as HMAC secret), weak HS256 secret,
  unverified `kid`/`jku`.
- Signed cookies / HMAC params: guessable secret, secret in a leaked bundle (hand from secrets), no signature check.
- Encrypted blobs: ECB (identical plaintext blocks -> identical ciphertext blocks), reused/static IV, CBC bit-flip.
- MAC construction: `H(secret||msg)` length-extension; `==` string compare on signatures (timing).

## Hunt methodology
1. Decode every token/cookie (base64url the JWT header/claims); note `alg`, structure, and any block regularity
   in ciphertext. `js-endpoints` + `scan-secrets` to hunt a signing secret leaked client-side.
2. Attack the CHEAPEST break first: `alg:none`, then alg-confusion, then offline weak-secret crack of the
   captured signature (wordlist), then structural (ECB/IV) and length-extension.
3. Confirm by REPLAYING a forged/modified artifact and observing acceptance (a differential vs the untampered
   control). For timing, average many samples of valid-prefix vs invalid signatures.

## Checks (predict -> send -> assert)
- technique: JWT alg:none / signature stripped
  send: re-sign the token with `alg:none` (empty signature), keeping/raising a claim (e.g. role), replay it
  predict: {status_in: [200], differs_from_control: true}   # control = tampered token WITH a bad signature
  refute_if: {status_in: [401, 403]}
  fp_note: the control (bad-sig) MUST be rejected; if both are accepted the endpoint ignores auth entirely, a
           different bug. Acceptance must reflect the forged claim taking effect.

- technique: alg confusion / weak-secret forge
  send: forge HS256 with the RSA public key as the secret, or a secret cracked offline from the captured sig; replay
  predict: {status_in: [200], body_contains: "<a value tied to the forged identity/role>", differs_from_control: true}
  refute_if: {status_in: [401, 403]}
  fp_note: prove the forged claim changed server behaviour (elevated data/role), not just that a 200 came back.

- technique: ECB / IV-reuse structure
  send: submit two inputs sharing a long repeated block; inspect the returned ciphertext for repeated blocks
  predict: {differs_from_control: false}   # identical plaintext blocks -> identical ciphertext blocks (control = single-block input)
  refute_if: {differs_from_control: true}
  fp_note: block-level repetition is the signal; a static IV shows as identical ciphertext for identical whole messages across requests.

- technique: signature timing (non-constant-time compare)
  send: many requests with a correct-prefix signature vs a wrong-first-byte signature
  predict: {latency_ms_gte: 4500}   # only meaningful if valid-prefix is measurably slower across averaged samples
  refute_if: {latency_ms_lt: 1500}
  fp_note: network jitter dwarfs byte-compare timing on most targets - treat as a weak lead, note open_proof_gap unless the delta is large and stable.

- technique: length-extension (H(secret||msg) MAC)
  send: with a hash-extender, append data and recompute the MAC without the secret; replay the extended message
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {status_in: [401, 403]}
  fp_note: only works for MD5/SHA1/SHA2 raw-concatenation MACs, not HMAC; confirm the extended payload is honoured.

## Notes
Severity: critical for token forgery yielding auth bypass/privilege escalation; high for a practical secret crack
or plaintext recovery; medium for a timing lead without a working forge. Evidence = the forged artifact and the
accept-vs-reject differential pair. Timing and OOB-less breaks stay open_proof_gap until a forged artifact is
actually accepted. Never forge tokens for identities you are not authorized to test.

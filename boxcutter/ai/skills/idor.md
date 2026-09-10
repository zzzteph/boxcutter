---
name: idor
label: IDOR / broken object-level authorization (BOLA)
triggers: [numeric-id, uuid-in-path, object-ref-param, api-id-path, ownership]
preconditions: [an authenticated identity and a control (anon or a second identity)]
scope: requests-only
safety: benign
severity_hint: high
---

# IDOR / broken object-level authorization (BOLA)

## Overview
An object reference in the request (an id in the path, a query param, a body field) selects a record, and the
server returns or mutates it without checking that the caller OWNS it. The bug is proven by comparison, never
by a single 200: the same request must succeed for a principal who should NOT be allowed and be refused for the
control.

## Attack surface
- Path ids: `/api/orders/1002`, `/users/42`, `/invoices/{uuid}`, `/files/{id}/download`.
- Params/body: `?account_id=`, `?doc=`, `{"user_id": 7}`, a hidden `owner`/`tenant` field.
- Enumerable refs: sequential integers, short ids, predictable slugs. UUIDs are still IDOR if the id leaks
  elsewhere (a list endpoint, a referrer, an email link).

## Hunt methodology
1. From recon/`get_traffic`, list every request that carries an object ref. `note_coverage` each.
2. Establish at least two viewpoints: your authenticated identity, and a control (anon, or a second account).
   Capture an object id that belongs to the OTHER viewpoint (from its own session, or by enumerating).
3. Replay the owner's request as the non-owner. Compare against the control response.
4. For write/mutate refs, prefer a read proof first (least-intrusive); only escalate to a state-changing PoC
   with an id you own. Never mutate another user's data.

## Checks (predict -> send -> assert)
- technique: cross-identity object READ
  send: as identity A, request an object id owned by identity B (or by anon)
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403, 404]}
  refute_if: {status_in: [401, 403, 404]}
  fp_note: a public object returns 200 for everyone - that is not IDOR. Confirm the body contains B's private
           data (an email, name, or a marker only B should see), and that the control is actually denied.

- technique: parameter/tenant swap
  send: as identity A, resend a request with the object/tenant ref changed to B's value
  predict: {status_in: [200], body_contains: "<a field value that belongs to B>", differs_from_control: true}
  refute_if: {status_in: [401, 403, 404]}
  fp_note: reflected input is not proof - the value must come from the SERVER's stored record for B.

- technique: unauthenticated object access
  send: as anon, request an object that should require a session
  predict: {status_in: [200], body_contains: "<private field>"}
  refute_if: {status_in: [401, 403]}
  fp_note: a soft-404/login page returned with 200 is not access - check the body is the real object.

## Notes
Severity: high when it exposes another user's private data or lets you act on their objects; critical if it
reaches admin objects or bulk data. The evidence is the two captured exchanges (owner-request-as-non-owner vs
the denied control) - cite both.

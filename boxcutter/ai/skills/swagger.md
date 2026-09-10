---
name: swagger
label: Swagger / OpenAPI spec exposure and abuse
triggers: [swagger-ui, openapi-spec, api-docs, swagger-json, v2-v3-spec]
preconditions: [a reachable OpenAPI/Swagger document or UI]
scope: requests-only
safety: benign
severity_hint: medium
---

# Swagger / OpenAPI spec

## Overview
A Swagger/OpenAPI document is the full map of the API's real surface - every operation, path, param and auth
requirement. Finding one is a lead, not a finding: the value is working the WHOLE operation list. Prove exposure
by fetching the spec and asserting it contains `openapi`/`swagger`, then treat each operation as a target -
unauthenticated data, enumerable object ids, live test/debug ops, and injectable params are each their own
finding. Never stop at "a spec exists".

## Attack surface
- The spec itself: `/swagger.json`, `/openapi.json`, `/v2/api-docs`, `/api-docs`, a Swagger/Redoc UI page.
- Operations that need no auth but return data; test/debug/internal ops left in the spec.
- Object-id path/query params across operations (the IDOR/BOLA map); every fuzzable param.

## Hunt methodology
1. `swagger-specs` to locate the spec (or spot the UI); confirm it loads. `note_coverage` the spec URL.
2. `api-map` / parse the spec to enumerate EVERY operation with its method, path, params and declared auth.
3. Replay each operation UNAUTHENTICATED with `http-request` to see which return data with no session; flag
   test/debug/admin-named ops.
4. On any operation with an object-id param, run the ID-enumeration (IDOR) play; `fuzz` each fuzzable param for
   injection. Keep proofs benign - read one record to prove access, don't bulk-dump.

## Checks (predict -> send -> assert)
- technique: spec exposed
  send: GET the candidate spec path (`/openapi.json`, `/v2/api-docs`, etc.)
  predict: {status_in: [200], body_contains: "openapi"}
  refute_if: {status_in: [401, 403, 404]}
  fp_note: an older Swagger 2.0 spec keys on `"swagger": "2.0"` instead - assert `body_contains: "swagger"`
           there. A UI HTML page is not the spec; find the JSON it loads.

- technique: unauthenticated operation returns data
  send: as anon, call an operation the spec lists (esp. GET list/detail ops) with no auth header
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403]}
  fp_note: control = an operation the spec marks as auth-required and that is denied anon. A public
           health/ping op returning 200 is not a finding - the body must be protected data.

- technique: test/debug operation live
  send: call an operation whose path/name signals test/debug/internal (`/debug`, `/test`, `/internal`, `/admin`)
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {status_in: [401, 403, 404]}
  fp_note: proof is the op actually functioning (returning state or performing its action), not merely routing.

- technique: object-id enumeration across an operation
  send: on an id-param operation, request an id belonging to another principal
  predict: {status_in: [200], body_contains: "<a field value belonging to that other object>", differs_from_control: true}
  refute_if: {status_in: [401, 403, 404]}
  fp_note: this is IDOR/BOLA proven via the mapped operation - the value must be the server's stored record for
           the other object, not reflected input. See the idor skill for the full differential.

## Notes
Severity: medium for a plainly exposed spec on its own; escalates to high/critical through the operations it maps
(unauth data, enumerable objects, injection). Evidence = the spec response proving exposure, plus the specific
operation exchange (and its denied control) for each downstream finding.

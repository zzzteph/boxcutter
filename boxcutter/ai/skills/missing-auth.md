---
name: missing-auth
label: Missing authentication / broken function-level authorization
triggers: [admin-path, api-endpoint, debug-console, internal-route, state-changing-endpoint, unauth-200]
preconditions: [an anon control; ideally a low-privilege identity too]
scope: requests-only
safety: benign
severity_hint: high
---

# Missing authentication / broken function-level authorization (BFLA)

## Overview
An endpoint performs a sensitive read or action but does not enforce that the caller is authenticated (missing
authn) or authorized for that FUNCTION (missing function-level authz / BFLA). Distinct from IDOR (which is
per-OBJECT ownership) and privesc (which is elevating a role): here the gate is simply absent or applied
inconsistently. Proven differentially - the sensitive endpoint answers for a principal who should be refused,
and the equivalent gated endpoint refuses the control.

## Attack surface
- Admin/management routes: `/admin`, `/api/admin/*`, `/internal/*`, `/actuator`, `/debug`, metrics/health.
- State-changing actions reachable without a session: create/delete/approve/export, `/api/*` writes.
- Inconsistent gates: a v2 route is gated but v1/legacy is not; the UI hides a button but the API is open;
  auth checked on GET but not on the mutating method.
- Endpoints found only in JS bundles / swagger that the UI never links (use js-endpoints, swagger-specs,
  api-map, katana-crawl, get_traffic to enumerate).

## Hunt methodology
1. Enumerate every endpoint (crawl + JS + spec + captured traffic). `note_coverage` each, including safe ones.
2. Hit each sensitive endpoint as `anon` (no session) and, if you have one, as a low-privilege identity.
3. Compare against the intended-gated behaviour: a properly protected sibling should return 401/403. A
   sensitive endpoint returning real data/effect to anon or a low-priv user is the finding.
4. Check per-method: if GET is gated, retry the state-changing verb; if v2 is gated, retry v1.
5. Keep proofs benign: prove READ access, or a harmless action on your own object; never destructive writes.

## Checks (predict -> send -> assert)
- technique: unauthenticated access to a sensitive endpoint
  send: as anon, request an admin/internal/data endpoint that should require a session
  predict: {status_in: [200], body_contains: "<privileged data marker>", differs_from_control: true}
  refute_if: {status_in: [401, 403]}
  fp_note: a 200 that is a login page / soft-404 / generic marketing body is not access - assert the body is
           the real privileged content, and that a truly gated endpoint returns 401/403 as the control.

- technique: broken function-level authz (low-priv reaches admin function)
  send: as a low-privilege identity, call an admin-only function
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403]}
  fp_note: the control (anon or the same call the app rejects for this role elsewhere) must actually be denied;
           a uniformly-open endpoint may just be public.

- technique: method / version gate gap
  send: the state-changing method (or the legacy v1 path) of an endpoint whose GET/v2 is gated
  predict: {status_in: [200, 201, 204], differs_from_control: true}
  refute_if: {status_in: [401, 403, 405]}
  fp_note: confirm the action actually took effect (re-read the object), not just a 200 acknowledgement.

## Notes
Severity: high for exposed sensitive data or admin functions; critical if it yields full admin control or bulk
data/actions. Evidence = the sensitive response as the disallowed principal PLUS the denied control - cite both.
Cross-refer: per-object ownership is [[idor]]; role elevation / mass-assignment is [[privesc]].

---
name: privesc
label: Web privilege escalation (role/tenant elevation, mass-assignment, function-level authz / BFLA)
triggers: [role, is_admin, tenant-id, org-id, profile-update, admin-endpoint, permissions, group, scope]
preconditions: [a low-privilege identity, and a control - a second identity or the admin/denied baseline]
scope: requests-only
safety: benign
severity_hint: critical
---

# Web privilege escalation (BFLA / vertical & horizontal)

## Overview
A low-privilege caller reaches a higher-privilege FUNCTION, or promotes themselves by setting a field the server
should own. Two shapes: broken function-level authorization (BFLA) - an admin/other-role endpoint answers a user
who should be denied; and mass-assignment - a role/tenant/permission field the client sends is trusted and
persisted. Proven only by comparison: the privileged action must SUCCEED for the account that should be refused
and be DENIED for the control. A single 200 is never enough.

## Attack surface
- Admin/management endpoints: `/admin/*`, `/api/*/users`, `/settings/org`, bulk-action and moderation routes.
- Role/permission fields in profile/registration/update bodies: `role`, `is_admin`, `admin`, `group`, `scope`,
  `permissions`, `plan`, `tier` (often hidden, discoverable via `js-endpoints` / `swagger-specs`).
- Tenant/org isolation: `tenant_id`, `org_id`, `company` in path/body - swap to another tenant.
- Verb/level gaps: a GET is gated but POST/PUT/DELETE on the same resource is not.

## Hunt methodology
1. Map the privileged surface: `api-map`, `swagger-specs`, `path-bust`, `js-endpoints` to find admin routes and
   the full field set of update/create bodies (look for role-ish fields the UI never shows).
2. Hold two viewpoints: a low-priv identity (test), and a control (admin baseline, a second tenant, or the denied
   anon). Capture what the privileged call looks like when done legitimately.
3. Replay the privileged FUNCTION as the low-priv identity; compare to the control.
4. For mass-assignment, add the role/tenant field to a normal self-update, then RE-FETCH your profile to confirm
   the elevation persisted server-side.
5. Benign proofs only: elevate your OWN test account, read (not alter) another tenant's marker, never touch real
   users' privileges. Revert any change you make to yourself.

## Checks (predict -> send -> assert)
- technique: function-level authz gap (BFLA)
  send: as the low-priv identity, call an admin/other-role endpoint (list users, change settings, moderate)
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403, 404]}
  refute_if: {status_in: [401, 403, 404]}
  fp_note: control = the SAME call as denied anon/other-role; the 200 must return privileged DATA or perform the
           privileged effect, not a shared/public view that everyone gets.

- technique: role mass-assignment
  send: add `role: admin` / `is_admin: true` / `permissions: [...]` to your own profile create/update
  predict: {status_in: [200, 201], body_contains: "admin", differs_from_control: true}
  refute_if: {status_in: [400, 403], body_not_contains: "admin"}
  fp_note: a reflected field is NOT proof - re-fetch your profile (control = your pre-change profile) and confirm
           the elevated role PERSISTED and now grants a previously-denied action.

- technique: cross-tenant elevation
  send: as tenant A, set/target `tenant_id`/`org_id` = B on an admin-scoped action
  predict: {status_in: [200], differs_from_control: true, control_status_in: [403, 404]}
  refute_if: {status_in: [403, 404]}
  fp_note: confirm the effect lands in B's data (a B-owned marker in the response); reflected id alone is not it.

- technique: verb / level tampering
  send: swap the method (GET->PUT/DELETE) or hit the privileged sibling route the UI hides
  predict: {status_in: [200, 201, 204], differs_from_control: true, control_status_in: [403, 405]}
  refute_if: {status_in: [403, 405]}
  fp_note: verify the write actually took effect (re-read), not that the server accepted an unusual verb with a
           no-op.

## Notes
Severity: critical when it yields admin or cross-tenant control; high for a self-elevation with limited reach.
Evidence for every check is the PAIR: the privileged action succeeding for the account that should be refused, and
the control being denied (differs_from_control + control_status_in). For mass-assignment, add the re-fetch proving
persistence. Chain a confirmed elevation to what it unlocks (user data, config, takeover) - do not stop at the 200.

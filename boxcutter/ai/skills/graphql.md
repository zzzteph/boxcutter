---
name: graphql
label: GraphQL abuse (introspection, BOLA/args, excessive data, mutations)
triggers: [graphql-endpoint, graphql-path, single-api-url, __typename, spa-graphql]
preconditions: [a GraphQL endpoint that answers a POST query body]
scope: requests-only
safety: benign
severity_hint: high
---

# GraphQL abuse

## Overview
A GraphQL endpoint is the WHOLE API surface behind one URL - never stop at "introspection enabled". Introspect
the schema, then reason generically about each field by its name, args and return type, and drive your own
`http-request` POSTs of `{"query":"..."}` bodies. Proofs: introspection returns `__schema`; a field returns
another principal's object/PII/credential; an arg reads a file; a single-request mutation grants privilege or
leaks a token. Each is a separate finding, most confirmed differentially against a control identity.

## Attack surface
- The endpoint: usually `/graphql` (also `/api/graphql`, `/query`, `/v1/graphql`) answering `{"query":"..."}`.
- Fields returning user/account/object types with sensitive scalar subfields.
- Field args: `id`/`code`/`slug`/`userId`/`orderId` (BOLA), `file`/`path`/`doc`/`template` (traversal).
- Mutations: register/signup, requestPasswordReset, loginAs/impersonate, checkout/refund/transfer.

## Hunt methodology
1. `graphql-detect` to confirm the endpoint and get its shape; `js-endpoints`/`katana-crawl` to find the URL in
   SPA bundles if not obvious. `note_coverage` the endpoint.
2. Introspect via `http-request` (a `__schema` query). Map every field, its args, and return types.
3. Walk fields generically: on any object-returning field select sensitive scalars; on any id/code arg pass
   values you were NOT given (1,2,3; sequential codes; a UUID seen elsewhere); on any file/path arg try
   traversal. Compare to a control identity.
4. Execute SINGLE-REQUEST mutations with real args and read the response - a dry-probe never proves them. Keep
   benign: read data, do not transfer money or destroy records.

## Checks (predict -> send -> assert)
- technique: introspection enabled
  send: POST an introspection query (`{"query":"{__schema{types{name}}}"}`)
  predict: {status_in: [200], body_contains: "__schema"}
  refute_if: {body_not_contains: "__schema"}
  fp_note: introspection is a disclosure lead, not itself high severity - use the schema to drive the real
           object/arg/mutation checks below.

- technique: excessive data / unauth sensitive field
  send: select a sensitive scalar (`password`,`token`,`apiKey`,`email`,`ssn`) on an object-returning field, unauth
  predict: {status_in: [200], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403]}
  fp_note: control = the same query with no/low-priv session denied. The returned value must be another
           principal's real secret, not a null field or your own data.

- technique: BOLA via id/code arg
  send: call a field with an `id`/`code`/`userId` you were not issued and select its private subfields
  predict: {status_in: [200], body_contains: "<a field value belonging to that other object>", differs_from_control: true}
  refute_if: {status_in: [401, 403, 404]}
  fp_note: the value must be the SERVER's stored data for the other object, not your input reflected.

- technique: path traversal via arg
  send: set a `file`/`path`/`doc`/`template` arg to `../../../../etc/passwd`
  predict: {status_in: [200], body_contains: "root:x:"}
  refute_if: {body_not_contains: "root:x:"}
  fp_note: the marker must be file contents in the field, not an error echoing your path.

- technique: dangerous single-request mutation
  send: execute a register with a `role`/`isAdmin` field, or a requestPasswordReset, or a loginAs, with real args
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {status_in: [400, 401, 403]}
  fp_note: proof is the response itself - a stuck privileged input (mass-assignment), a reset token RETURNED in
           the body, or a minted foreign token. Verbose `extensions` stack traces are separate disclosure.

## Notes
Severity: high for another principal's object/PII, file read, or a mutation privilege grant; critical when a
minted/impersonation token or leaked reset token yields account takeover - CHAIN it. Evidence = the query and
the response, plus the denied control for auth-scoped findings.

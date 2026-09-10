---
name: nosql
label: NoSQL injection (operator injection, auth bypass)
triggers: [json-login, query-param, filter-object, mongo-hint, search, id-param]
preconditions: []
scope: requests-only
safety: benign
severity_hint: critical
---

# NoSQL injection

## Overview
User input reaches a document-store query (MongoDB and kin) where an attacker-supplied operator or type changes
the query's meaning - `{"$ne": null}` matches everything, `{"$gt": ""}` bypasses a check, `$where`/`$regex`
smuggle logic. Prove it by making the store return or authorize differently under an operator payload versus a
literal-string control. A single 200 is a lead; confirmation is always differential.

## Attack surface
- JSON logins/APIs where a string field can be swapped for an object: `{"user":"admin","pass":{"$ne":null}}`.
- Query params parsed into query objects: `?user[$ne]=x`, `?age[$gt]=0`, `?q[$regex]=.*`.
- Filter/sort/search bodies, id lookups, and any field concatenated into a `$where` JS expression.
Map with `katana-crawl`, `js-endpoints`, `api-map`, `swagger-specs`.

## Hunt methodology
1. Find inputs that reach a query - especially JSON bodies and bracketed query params.
2. Run `fuzz` with `{FUZZ}` on one field; its payload DB includes NoSQL operator payloads and self-confirms
   against the unfuzzed baseline. Reproduce confirmed hits with `http-request`.
3. Confirm the CLASS with a differential pair below. Keep it benign: prove auth-bypass/over-match or a boolean
   flip, never delete or mass-export documents.

## Checks (predict -> send -> assert)
- technique: authentication bypass via operator
  send: replace the password string with `{"$ne": null}` (or `{"$gt": ""}`); control = a wrong literal password
  predict: {status_in: [200, 302], differs_from_control: true, control_status_in: [401, 403]}
  refute_if: {status_in: [401, 403], differs_from_control: false}
  fp_note: the response must be an AUTHENTICATED state (session cookie / user data), not a generic 200 login page.

- technique: query-param operator injection (over-match)
  send: `?field[$ne]=nonexistent1337` vs control `?field=nonexistent1337`
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {differs_from_control: false}
  fp_note: `$ne` should return MANY records vs the empty literal result; a framework that rejects bracket params
           (400) is not injectable. Differ in row/content count, not in a timestamp.

- technique: boolean-based blind ($regex / $where)
  send: TRUE `{"$regex":".*"}` vs FALSE `{"$regex":"^nomatch1337$"}` on a filtered field
  predict: {status_in: [200], differs_from_control: true}    # control = the FALSE payload
  refute_if: {differs_from_control: false}
  fp_note: the TRUE/FALSE responses must differ in returned content; re-fire to confirm stability.

- technique: time-based blind ($where JS)
  send: `$where` payload with a sleep, e.g. `{"$where":"sleep(5000)||true"}`, vs a `sleep(0)` control
  predict: {latency_ms_gte: 4500, differs_from_control: true}
  refute_if: {latency_ms_lt: 1500}
  fp_note: many stacks disable `$where`; a uniformly slow endpoint is not proof - the delay must track the payload.

## Notes
Severity: critical when it yields auth bypass or bulk data reach; high for a confirmed boolean/over-match with
limited scope. Evidence = the operator-vs-literal exchange pair (or the authenticated-vs-denied pair). A
confirmed bypass is the start of the finding - note what it reaches, keep all proofs read-only.

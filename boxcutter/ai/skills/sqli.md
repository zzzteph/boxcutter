---
name: sqli
label: SQL injection (in-band, blind boolean/time, error, OOB)
triggers: [query-param, search, filter, sort, id-param, login, json-field]
preconditions: []
scope: requests-only
safety: benign
severity_hint: critical
---

# SQL injection

## Overview
User input reaches a SQL query unparameterised. Prove it by making the DATABASE behave differently in a way the
harness can measure: a boolean pair that flips the response, a time delay that tracks the payload, a database
error surfaced, or an out-of-band callback. A single odd response is a lead, not a finding - the confirmation is
always differential (payload vs control).

## Attack surface
Any value that could land in a WHERE/ORDER BY/LIMIT/INSERT: search boxes, filters, `id`/`sort`/`order` params,
pagination, login fields, JSON body fields, headers used in queries. `get_traffic` to enumerate every param.

## Hunt methodology
1. Reach for `fuzz` first: point `{FUZZ}` at one param of a realistic request; it carries a built-in payload
   DB (incl. sqli), baselines each hit against the unfuzzed response, and self-confirms. Trust its confirmed
   hits.
2. When `fuzz` flags a candidate, confirm the CLASS with an explicit differential pair (below), then use
   `sqlmap` on the exact injectable request to prove exploitability / extract (least data needed to prove).
3. Keep every proof benign: read one row / a version string, never DROP/UPDATE/DELETE, never dump at scale.

## Checks (predict -> send -> assert)
- technique: boolean-based blind
  send: two requests to ONE param - a TRUE payload (e.g. `' OR '1'='1`) and a FALSE payload (`' AND '1'='2`)
  predict: {status_in: [200], differs_from_control: true}    # control = the FALSE payload response
  refute_if: {differs_from_control: false}
  fp_note: the TRUE/FALSE responses must differ in a content-meaningful way (row count, presence of results),
           not in a nonce/CSRF token or timestamp; re-fire to confirm it is stable.

- technique: time-based blind
  send: inject a DB sleep into one param (e.g. `'; SELECT pg_sleep(5)--` / `' OR SLEEP(5)-- -`)
  predict: {latency_ms_gte: 4500, differs_from_control: true}   # control = a sleep(0) / benign variant
  refute_if: {latency_ms_lt: 1500}
  fp_note: a uniformly slow endpoint is not proof - the delay must TRACK the payload (sleep(5) ~5s,
           sleep(0) fast). Re-fire both to rule out jitter.

- technique: error-based
  send: a syntax-breaking payload (`'`, `")`, `'||`)
  predict: {body_contains: ["SQL", "syntax"]}                  # adapt to the DB's real error text
  refute_if: {status_in: [200], body_not_contains: "SQL"}
  fp_note: a generic 500 page is not an SQL error - the body must reveal DB syntax/driver text.

- technique: OOB (when blind and no timing)
  send: a payload that makes the DB resolve/fetch an attacker-controlled host
  predict: {}    # not gradeable here - confirm via an out-of-band hit; record as open_proof_gap until observed
  fp_note: only a real callback from the target's backend confirms it.

## Notes
Severity: critical when it reaches data extraction or auth bypass; high for a confirmed injection with limited
reach. Evidence = the differential exchange pair (or the sqlmap-confirmed request). A confirmed SQLi is the
START of the finding - note what it can reach (auth bypass, data), don't stop at "injectable".

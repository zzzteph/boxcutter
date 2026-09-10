---
name: info_disclosure
label: Information disclosure (over-serialization, exposed storage/config, GraphQL over-fetch, verbose errors, source maps)
triggers: [api-json, user-object, graphql-endpoint, stacktrace, error-500, source-map, s3-url, backup-file, dotfile]
preconditions: []
scope: requests-only
safety: benign
severity_hint: medium
---

# Information disclosure

## Overview
The server hands back more than the caller needs: extra object fields, another user's data, internal config, stack
traces, buckets, or `.map` files that rebuild source. Each class is proven by FETCHING one artifact and asserting
its body contains a specific secret/PII/error signature - one leaked value is proof, never enumerate at scale.

## Attack surface
- Over-serialization: API objects carrying `password_hash`, `ssn`, `is_admin`, internal ids, tokens beside the
  fields the UI shows.
- GraphQL over-fetch: introspection on, or queries that pull fields no client uses.
- Storage/config: `s3.amazonaws.com`/`storage.googleapis.com` URLs, `.env`, `config.php`, `web.config`,
  `.git/config`, `backup.zip`, `db.sql`, `.DS_Store`.
- Errors: stack traces, framework debug pages, SQL/driver text, absolute paths, version banners.
- Source maps: `//# sourceMappingURL=` in JS bundles -> `*.js.map` with original source/comments.

## Hunt methodology
1. `api-map` / `swagger-specs` / `graphql-detect` to enumerate endpoints and schema; `katana-crawl` +
   `js-endpoints` for bundles and referenced assets.
2. `path-bust` for common config/backup/dotfile names; `nuclei` for known exposure templates.
3. For over-fetch, diff the JSON object against what the UI actually renders - flag surplus sensitive fields.
4. Pull ONE proof per class (a single map file, one bucket object, one over-fetched record). Stop at proof.

## Checks (predict -> send -> assert)
- technique: over-serialized API object
  send: request a user/order/account object and inspect the returned JSON
  predict: {status_in: [200], body_contains: ["password", "is_admin", "ssn", "token"]}   # adapt to the app's sensitive keys
  refute_if: {body_not_contains: "password"}
  fp_note: the field must carry a real VALUE (a hash, a flag), not an empty/nulled placeholder or a public attribute.

- technique: GraphQL introspection / over-fetch
  send: an introspection query, then a query pulling sensitive fields on a type the client never requests
  predict: {status_in: [200], body_contains: ["__schema", "email"]}
  refute_if: {body_contains: ["introspection", "disabled"], body_not_contains: "__schema"}
  fp_note: introspection being on is low sev alone; the finding is a query returning data the caller should not see.

- technique: exposed config / backup / dotfile
  send: fetch a guessed artifact (`/.env`, `/.git/config`, `/backup.zip`, `/config.php.bak`)
  predict: {status_in: [200], body_contains: ["=", "APP_KEY", "[core]", "DB_PASSWORD"]}
  refute_if: {status_in: [403, 404]}
  fp_note: a 200 soft-404/HTML page is not the file - the body must be the real config/archive/repo content.

- technique: source map recovery
  send: fetch the `.map` referenced by a JS bundle (or guess `bundle.js.map`)
  predict: {status_in: [200], body_contains: ["\"sources\"", "\"sourcesContent\""]}
  refute_if: {status_in: [403, 404]}
  fp_note: confirms source recovery; escalate only if the recovered source reveals a secret/endpoint (hand to secrets/crypto).

- technique: verbose error / stack trace
  send: a malformed request (bad type, missing field, oversized value) to force an error
  predict: {status_in: [500], body_contains: ["Traceback", "at java.", "Stack trace", "Exception"]}
  refute_if: {body_not_contains: "at "}
  fp_note: a styled generic error page is not disclosure - the body must leak paths, versions, or driver internals.

## Notes
Severity: scales with what leaked - low/medium for versions and stack traces, high for PII/credentials/another
user's data or a readable `.git`/backup. Evidence = the single fetched artifact and the exact leaked line. Never
bulk-download a bucket or a repo; one object proves the exposure.

---
name: injection
label: Other injection (LDAP, object/type confusion, HTML/CSS, protocol-field, path/unicode)
triggers: [login-filter, search-directory, type-coercion-param, html-into-pdf, header-field, path-param, unicode-normalize]
preconditions: []
scope: requests-only
safety: benign
severity_hint: high
---

# Other injection (LDAP / object-type / markup / protocol-field / path)

## Overview
A grab-bag of injections where untrusted input breaks out of the syntax of a downstream consumer that is NOT a
SQL/NoSQL/template/OS-command sink. The consumer may be an LDAP filter, a type-coercing parser, an HTML/CSS
renderer, a protocol field (header/log/email), or a path resolver. Prove each by making the consumer behave
differently under a breaking payload versus a benign control - never by a lone anomaly.

## Attack surface
- LDAP: login/search filters (`uid=`, `cn=`) that build `(&(...))` queries.
- Object/type confusion: params parsed as JSON where a string vs `{}`/`[]`/number changes logic.
- HTML/CSS: input rendered into server-side HTML/PDF (invoices, exports) or a style attribute.
- Protocol-field: values placed into headers, logs, or email envelopes (CRLF, header splitting).
- Path/unicode: path segments and names that normalize or traverse (`..`, `%2e`, overlong UTF-8, `?/#`).
Map inputs with `katana-crawl`, `js-endpoints`, `api-map`, `swagger-specs`, `path-bust`.

## Hunt methodology
1. Classify each input by its likely downstream consumer (directory, parser, renderer, protocol, filesystem).
2. Run `fuzz` with `{FUZZ}` on one param - its DB carries LDAP, traversal, and CRLF payloads and self-confirms
   against the baseline. Use `path-bust` for path/traversal breadth. Reproduce hits with `http-request`.
3. Confirm the CLASS with a differential pair below; keep payloads read-only (probe filters/paths, never write).

## Checks (predict -> send -> assert)
- technique: LDAP filter injection (boolean flip)
  send: a TRUE payload `*)(uid=*))(|(uid=*` vs a FALSE payload `*)(uid=nonexistent1337`
  predict: {status_in: [200], differs_from_control: true}    # control = the FALSE payload response
  refute_if: {differs_from_control: false}
  fp_note: the two must differ in result content (records returned / auth outcome), not in a nonce; re-fire.

- technique: object/type confusion
  send: send a field as `{}`/`[]`/`true`/number where a string is expected (e.g. `"admin"` -> `{"$ne":null}`-shaped or `true`)
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {status_in: [400, 422], differs_from_control: false}
  fp_note: a 400 "invalid type" is the parser rejecting you, not confusion. Proof = the type change alters logic
           (auth granted, filter bypassed) vs the string control.

- technique: HTML/markup injection into server-rendered output
  send: a benign tag marker into a field that lands in server HTML/PDF, e.g. `<b id=inj1337>x</b>`
  predict: {status_in: [200], body_contains: "id=inj1337", differs_from_control: true}
  refute_if: {body_not_contains: "inj1337"}
  fp_note: the marker must appear UNESCAPED (raw `<b`), not entity-encoded `&lt;b`; encoded = safe reflection.

- technique: protocol-field / CRLF header injection
  send: a value with encoded CRLF + an injected header, e.g. `x%0d%0aX-Inj: 1337`
  predict: {header_contains: "X-Inj", status_in: [200, 302]}
  refute_if: {status_in: [400], header_contains: ""}
  fp_note: the injected header must appear in the RESPONSE; if the stack strips CRLF you get a 400 - not vulnerable.

- technique: path / unicode traversal
  send: `../` / `%2e%2e%2f` / overlong `%c0%ae` sequences toward a known file marker via `path-bust`
  predict: {status_in: [200], body_contains: "root:", differs_from_control: true}    # e.g. /etc/passwd token
  refute_if: {status_in: [400, 403, 404]}
  fp_note: match on file-specific content (`root:x:0:0`), not a 200 alone; a soft-404 body with 200 is not a read.

## Notes
Severity: high (LDAP auth bypass, traversal file read, header/response splitting); critical if it reaches full
account takeover or arbitrary file read of secrets. Evidence = the breaking-payload-vs-control pair, with the
unescaped/leaked marker cited. Keep every probe read-only.

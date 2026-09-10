---
name: xss
label: Cross-site scripting (reflected, stored, DOM)
triggers: [reflected-param, form-field, path-echo, header-echo, innerHTML, document-write, eval, location-sink]
preconditions: []
scope: requests-only
safety: benign
severity_hint: high
---

# Cross-site scripting (XSS)

## Overview
User input reaches an HTML response (or a DOM sink) without the right encoding, so a marker you supply is parsed
as markup/script instead of text. Reflected XSS is provable by the harness when your marker lands UNESCAPED in an
executable HTML context; stored and DOM XSS need a render step - assert what you can and mark the execution proof
as open until observed. A reflection in a non-HTML response (JSON, `application/javascript`, plain text) does not
execute and is not XSS.

## Attack surface
- Reflected: any input echoed into the response - query params, form fields, path segments, echoed headers.
- Stored: fields persisted then re-rendered - profile fields, comments, filenames, support messages; the field
  an ADMIN later views is the high-value case.
- DOM: client-side sinks in the JS - `innerHTML`, `document.write`, `eval`, `location`; `js-endpoints` and
  `katana-crawl` surface them.

## Hunt methodology
1. Run `fuzz` on each reflected param - it context-tests payloads, enforces an HTML Content-Type gate, and self-
   confirms reflected XSS. Trust its confirmed hits; they already exclude non-HTML reflections.
2. Match the payload to the reflection CONTEXT: HTML body vs an attribute (`"` break-out) vs a `<script>` JS-
   string vs a URL/`href` (`javascript:`) vs an event handler.
3. For STORED: persist a unique marker payload, then request the view that renders it back; confirm it lands
   unescaped there. Prioritise fields an admin views.
4. For a DOM sink, confirm the payload actually EXECUTES in a real browser render, not merely that it reflects.
5. Keep proofs benign: a marker like `<xss-boxcutter>` or `alert(document.domain)`, never a real payload.

## Checks (predict -> send -> assert)
- technique: reflected XSS in HTML body
  send: set the param to a unique unescaped marker, e.g. `<xss-boxcutter>` (or `"><svg onload=...>`)
  predict: {status_in: [200], body_contains: "<xss-boxcutter>", header_contains: "Content-Type: text/html"}
  refute_if: {body_contains: "&lt;xss-boxcutter&gt;", header_contains: "Content-Type: application/json"}
  fp_note: the marker must appear RAW (angle brackets intact) in a `text/html` response. HTML-encoded output
           (`&lt;`) is safe; a reflection in JSON/JS/plain text does not execute - not XSS.

- technique: attribute break-out
  send: a value that closes the attribute and opens a handler, e.g. `"><img src=x onerror=alert(1)>`
  predict: {status_in: [200], body_contains: "\"><img src=x onerror=alert(1)>", header_contains: "Content-Type: text/html"}
  refute_if: {body_contains: "&quot;&gt;", body_not_contains: "onerror=alert(1)"}
  fp_note: the quote/bracket must survive unescaped so the handler lands in an executable position; if the quote
           is entity-encoded the break-out failed.

- technique: stored XSS (persist then render)
  send: persist a unique marker payload, then request the view that renders the field
  predict: {status_in: [200], body_contains: "<xss-boxcutter>", header_contains: "Content-Type: text/html"}
  refute_if: {body_contains: "&lt;xss-boxcutter&gt;"}
  fp_note: assert on the RENDERED view, not the write response. Confirm the marker is unescaped where it is
           displayed; execution in an admin view is the high-value case.

- technique: DOM-based XSS
  send: a payload targeting a client-side sink (e.g. a fragment/param read into `innerHTML`)
  predict: {}    # not gradeable server-side - confirm execution in a real browser render; open_proof_gap until observed
  refute_if: {}
  fp_note: the source value never reaches the server, so a body assertion cannot prove it; only an actual
           execution in the rendered DOM confirms it.

## Notes
Severity: high for a confirmed executing payload; escalate the finding by chaining - a stored XSS in an admin-
viewed field is session theft / account takeover, a reflected XSS with a crafted GET delivery link is a report on
its own. Evidence = the response showing the unescaped marker in an executable HTML context (or the observed
render for stored/DOM). Do not stop at "it reflects" - reflection alone is not XSS.

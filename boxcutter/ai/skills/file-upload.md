---
name: file-upload
label: Unrestricted / unsafe file upload
triggers: [multipart-form, file-input, avatar-upload, attachment, document-upload]
preconditions: [an upload endpoint and a way to fetch the stored file back]
scope: requests-only
safety: benign
severity_hint: high
---

# File upload

## Overview
An upload endpoint accepts a file and stores it somewhere reachable. The bug is that the server fails to
constrain WHAT you upload or WHERE it lands - so a file gets served with a dangerous type, renders active
content, or is written outside its intended path. Proof is always: upload a BENIGN marker file, then fetch it
back and observe how the server treats it (served verbatim, rendered, or executed). Never upload a destructive
webshell - a benign unique marker is enough to prove each class.

## Attack surface
- What is enforced: extension allow/deny, `Content-Type`, magic bytes, size, filename sanitisation.
- Where it lands: is the upload dir web-served? executable? Can the filename steer the path (`../`)?
- Rendering sinks: SVG/HTML served inline (stored XSS), XML-based formats (XXE), archive extraction (zip-slip).

## Hunt methodology
1. From recon/`get_traffic`, find every upload and its retrieval URL. `note_coverage` each pair.
2. Baseline: upload a plain allowed file (e.g. a real `.jpg`) with a unique marker in it, fetch it back, and
   record the served path, `Content-Type`, and whether the body is byte-identical.
3. Probe enforcement one axis at a time (extension, content-type, magic bytes) with benign markers; watch what
   the RETRIEVAL does with each.
4. Prefer least-intrusive proofs: a served-verbatim marker or a rendered SVG proves the class without any
   executing payload. Only note an exec sink as a gap if you cannot prove it benignly.

## Checks (predict -> send -> assert)
- technique: extension / type filter bypass (served verbatim)
  send: upload `marker.php.jpg` / `.pHp` / `.phtml` etc. with a unique benign string, then GET the stored file
  predict: {status_in: [200], body_contains: "<the unique marker>", header_contains: "application/octet-stream"}
  refute_if: {status_in: [403, 415]}
  fp_note: served verbatim is a filter bypass, not yet RCE. RCE requires the server to EXECUTE it - assert that
           benignly (a marker the server would only emit if it ran the file), never a destructive shell.

- technique: stored XSS via rendered upload
  send: upload an SVG/HTML file containing a benign marker element, then fetch it and check how it is served
  predict: {status_in: [200], body_contains: "<the marker>", header_contains: "image/svg+xml"}
  refute_if: {header_contains: "text/plain"}
  fp_note: proof of stored XSS is the file served with a renderable content-type inline (not
           `Content-Disposition: attachment` / `text/plain`), so a browser would execute it.

- technique: path traversal in filename
  send: upload with filename `..%2f..%2fmarker.txt`, then request the traversed target path
  predict: {status_in: [200], body_contains: "<the marker>", differs_from_control: true}
  refute_if: {status_in: [400, 403, 404]}
  fp_note: control = the file at its intended path; proof is the marker appearing at the DIFFERENT (traversed)
           location, showing the write escaped its directory.

- technique: content-type / magic-byte mismatch accepted
  send: upload a file whose declared `Content-Type` (or magic bytes) contradicts its real extension
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {status_in: [415, 422]}
  fp_note: acceptance alone is weak; pair it with a retrieval that shows the mismatch is actually dangerous
           (served executable/renderable), else it is informational.

## Notes
Severity: critical if a served file executes (proven with a benign RCE marker); high for stored XSS via an
inline-rendered upload or a traversal write; XXE via an XML-based upload is a separate finding (see xxe). Keep
every proof benign - a unique marker fetched back is the evidence, cite the upload request and the retrieval.

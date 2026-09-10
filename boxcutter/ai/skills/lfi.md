---
name: lfi
label: Path traversal / local file inclusion (LFI)
triggers: [file, path, doc, template, page, include, download, view, dir, report, export, preview]
preconditions: []
scope: requests-only
safety: benign
severity_hint: high
---

# Path traversal / local file inclusion

## Overview
A param names a file or path the server reads, and unsanitised traversal sequences let you step outside the
intended directory to read arbitrary files - or, when the file is INCLUDED rather than just read, to reach code
execution. Proof is the contents of a file outside the intended directory appearing in the response, confirmed
differentially against the normal (in-bounds) request.

## Attack surface
- Params that name a file/path: `file`, `path`, `doc`, `template`, `page`, `include`, `download`, `view`, `dir`,
  `report`.
- Features: download/preview/export/report generators, template loaders, "view attachment" endpoints.
- Targets: `/etc/passwd`, `C:\windows\win.ini`, app source, config files with secrets, `/proc/self/environ`.

## Hunt methodology
1. From recon and `api-map`, list every request whose param resolves to a file; `fuzz` a traversal payload set
   at one param and let it baseline against the in-bounds response.
2. Traverse to a known file: `../../../../etc/passwd`, `..\..\..\windows\win.ini`. Recognisable contents back =
   traversal.
3. Bypasses: URL-/double-encoding (`%2e%2e%2f`, `%252e`), a null byte, an absolute path (`/etc/passwd`), nested
   traversal (`....//`), or prefixing the legitimate directory the filter expects.
4. If the file is INCLUDED (executed) not just read, escalate LFI->RCE: `php://filter` to read source, log
   poisoning, session files, or `/proc/self/environ`. Note the vector; keep the PoC benign.
5. Keep proofs benign: read one well-known low-sensitivity file to demonstrate reach, not secrets at scale.

## Checks (predict -> send -> assert)
- technique: unix path traversal
  send: set the file param to `../../../../etc/passwd`
  predict: {status_in: [200], body_contains: "root:", differs_from_control: true}   # control = the in-bounds file
  refute_if: {status_in: [400, 403, 404], body_not_contains: "root:"}
  fp_note: the body must contain real file contents (`root:x:0:0:` lines), not an error page or the app's normal
           content; confirm it differs from the legitimate in-bounds response.

- technique: windows path traversal
  send: set the file param to `..\..\..\..\windows\win.ini`
  predict: {status_in: [200], body_contains: "[fonts]", differs_from_control: true}
  refute_if: {status_in: [400, 403, 404], body_not_contains: "[extensions]"}
  fp_note: assert on a stable marker from the file (`[fonts]`/`[extensions]`), not just a 200; a soft-404 with
           200 is not a read.

- technique: encoding / filter bypass
  send: re-send the traversal encoded, e.g. `%2e%2e%2f%2e%2e%2fetc%2fpasswd` or `....//....//etc/passwd`
  predict: {status_in: [200], body_contains: "root:", differs_from_control: true}
  refute_if: {status_in: [400, 403, 404]}
  fp_note: confirm the encoded variant reaches the SAME out-of-bounds file the raw attempt was blocked from.

- technique: php://filter source disclosure (inclusion sink)
  send: set the param to `php://filter/convert.base64-encode/resource=index.php`
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {status_in: [400, 403], differs_from_control: false}
  fp_note: a base64 blob that decodes to PHP source confirms an inclusion sink (LFI, not just read); a normal
           rendered page means the wrapper was not honoured. RCE via log/session poisoning stays open until
           execution is observed - record as open_proof_gap.

## Notes
Severity: high for reading files outside the intended directory (system files, app source, configs with
secrets); critical when the file is executed via inclusion (LFI->RCE). Evidence = the response containing the
out-of-bounds file contents, cited against the in-bounds control. Note whether the sink merely reads or includes.

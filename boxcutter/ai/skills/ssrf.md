# Server-side request forgery (SSRF)

**Trigger:** an endpoint takes a URL/host the server then fetches - a param like `url`/`uri`/`callback`/`webhook`/`image`/`feed`/`proxy`/`dest`, a "fetch from URL" / "import from link" / webhook feature, or a PDF/screenshot/preview generator.

**Action:**
- Point it at your own out-of-band listener (a unique host you control) and watch for the callback - a request arriving = blind SSRF even when no response is shown.
- Try internal targets: `http://127.0.0.1:<port>`, `http://localhost`, `http://169.254.169.254/latest/meta-data/` (cloud metadata), `http://[::1]`, and internal hostnames the app hinted at.
- Bypass filters: alternate IP encodings (decimal/octal/hex), a redirect you control that 302s to the internal target, `http://attacker.com@internal`, DNS rebinding, a trailing dot, or a different scheme (`file://`, `gopher://`, `dict://`).

**Confirm:** an out-of-band hit from the server, or internal/metadata content reflected back, is SSRF. Cloud metadata credentials = critical (chain to the cloud account). Note whether it is blind (callback only) or full-response.

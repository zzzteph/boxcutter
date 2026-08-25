# File upload

**Trigger:** an upload endpoint or form - `multipart/form-data`, `<input type=file>`, an avatar/document/attachment feature.

**Action:**
- Test what the server enforces: extension (`.php`/`.jsp`/`.aspx`/`.svg`/`.html`), Content-Type, magic bytes, and where the file lands (is it web-served and executable?).
- Bypasses: double extension (`shell.php.jpg`), null byte, case (`.pHp`), alternate executable extensions (`.phtml`, `.php5`, `.asp;.jpg`), a polyglot (valid image + code), or a `.htaccess`/`web.config` to make the dir execute.
- Non-exec wins: an SVG or HTML upload that renders = stored XSS; an XML-based format = XXE; a `../../` path in the filename = traversal / overwrite; a huge file = DoS.
- Find where it is served and request it back to confirm.

**Confirm:** a served file that EXECUTES (a benign RCE marker in the response) is critical; a rendered SVG/HTML (stored XSS), an XXE, or a traversal write are each separate findings.

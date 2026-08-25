# Cross-site scripting (XSS)

**Trigger:** the app reflects user input (a query param, form field, path, or header echoed into the response), or a DOM sink appears in the JS (juicy flags `innerHTML` / `document.write` / `eval` / `location`).

**Action:**
- Run `fuzz` on each reflected parameter - it context-tests payloads and self-confirms reflected XSS.
- For a DOM sink juicy surfaced, confirm the payload actually EXECUTES in a real browser render, not just that it reflects.
- Try STORED: persist a payload (profile field, comment, filename, support message) then view it back - stored XSS in a field an ADMIN views is the high-value case.
- Match the payload to the reflection CONTEXT: HTML body vs an attribute (`"` break-out) vs a `<script>` JS-string vs a URL/`href` (`javascript:`) vs an event handler.

**Not XSS - do not report:** a reflection in a response whose `Content-Type` is `application/javascript` / JSON / plain text. Only a response the browser renders as HTML executes; the fuzzer already enforces this HTML gate, so trust it.

**Confirm + chain:** an executing payload is XSS. Chain a stored XSS in an admin-viewed field to admin-session theft / account takeover; a reflected XSS with a delivery vector (a crafted GET link) is a real report on its own.

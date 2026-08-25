# CORS misconfiguration

**Trigger:** the API returns an `Access-Control-Allow-Origin` header (a cross-origin app, a JSON API read from the browser).

**Action:** replay a request with a crafted `Origin` header and inspect the response:
- **Reflected origin + credentials** - `Access-Control-Allow-Origin: <your-evil-origin>` together with `Access-Control-Allow-Credentials: true` = any site can read this user's authenticated data. High.
- **`null` origin** - send `Origin: null`; if it is reflected + credentialed, a sandboxed iframe can exploit it.
- **Weak matching** - try `evil.com`, `target.com.evil.com`, `eviltarget.com`, `sub.target.com`; a prefix/suffix/substring match that reflects your origin is exploitable.

**Confirm:** an attacker-controllable origin reflected in `Access-Control-Allow-Origin` WITH credentials allowed lets a malicious page read the victim's authenticated responses = a real finding. Without credentials it only matters for non-authenticated data.

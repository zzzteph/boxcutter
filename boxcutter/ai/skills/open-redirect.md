# Open redirect

**Trigger:** a param that controls where the app sends the browser - `redirect`/`redirect_uri`/`next`/`return`/`returnUrl`/`continue`/`url`/`dest`/`goto`, often on login/logout/SSO flows.

**Action:**
- Set it to an external origin (`https://evil.example`) and follow the response - a 3xx `Location:` or a client-side redirect to your host = open redirect.
- Bypass naive checks: `//evil.example`, `https:evil.example`, `https://target.example.evil.example`, `https://evil.example\@target`, a backslash `\/\/`, whitespace/control chars, or double-encoding.

**Confirm:** the app redirects to an attacker-controlled host = open redirect. Usually low on its own, but CHAIN it: OAuth/SSO `redirect_uri` takeover to steal a token/code, phishing that lands on the trusted domain, or SSRF when the redirect is followed server-side.

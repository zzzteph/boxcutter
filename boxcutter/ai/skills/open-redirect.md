---
name: open-redirect
label: Open redirect (unvalidated redirect / forward)
triggers: [redirect, redirect_uri, next, return, returnUrl, continue, url, dest, goto, login-flow, logout-flow, sso]
preconditions: []
scope: requests-only
safety: benign
severity_hint: low
---

# Open redirect

## Overview
A param controls where the app sends the browser, and the app forwards to an attacker-supplied origin without
validating it stays on-site. Proof is a 3xx whose `Location` header points at a host you control (or a client-
side redirect to it). Low on its own, but it CHAINS: OAuth/SSO `redirect_uri` takeover to steal a code/token,
phishing that lands on the trusted domain, or SSRF when the redirect is followed server-side.

## Attack surface
- Redirect params: `redirect`, `redirect_uri`, `next`, `return`, `returnUrl`, `continue`, `url`, `dest`, `goto`.
- Flows: login, logout, SSO/OAuth callbacks, post-action "back to" links, interstitial "leaving site" pages.
- Sinks: a `Location` header (server-side 3xx) or a JS `location`/`window.location` assignment (client-side).

## Hunt methodology
1. From recon, list every request whose param names a destination; `js-endpoints` and `katana-crawl` to find
   client-side redirect sinks. `note_coverage` each.
2. Set the param to an external origin (`https://evil.example`) and DO NOT auto-follow - inspect the raw
   `Location` header on the 3xx.
3. If a naive check blocks it, try bypasses: `//evil.example`, `https:evil.example`,
   `https://target.example.evil.example`, `https://evil.example\@target`, a backslash `\/\/`, whitespace/control
   chars, or double-encoding.
4. Use a distinctive attacker host so the assertion is unambiguous; keep the destination benign.

## Checks (predict -> send -> assert)
- technique: server-side redirect to external origin
  send: set the redirect param to `https://evil.example` and read the response WITHOUT following
  predict: {status_in: [301, 302, 303, 307, 308], header_contains: "Location: https://evil.example"}
  refute_if: {header_contains: "Location: /", status_in: [200]}
  fp_note: the `Location` must resolve to the attacker host, not a same-site path with the value merely appended
           as a query string. A relative `Location` back to the app is not a redirect off-site.

- technique: scheme-relative / protocol-relative bypass
  send: set the param to `//evil.example` (or `https:evil.example`, `\/\/evil.example`)
  predict: {status_in: [301, 302, 303, 307, 308], header_contains: "Location: //evil.example"}
  refute_if: {header_contains: "Location: /", status_in: [200]}
  fp_note: confirm the browser would treat the `Location` as an absolute off-site URL, not a path on the target.

- technique: allow-list bypass via crafted host
  send: set the param to `https://target.example.evil.example` or `https://evil.example\@target`
  predict: {status_in: [301, 302, 303, 307, 308], header_contains: "Location: https://target.example.evil.example"}
  refute_if: {header_contains: "Location: https://target", status_in: [200]}
  fp_note: the final host the browser resolves must be attacker-controlled; a suffix/prefix that still lands on
           the real target is not a bypass.

## Notes
Severity: low standalone; escalate the finding when it chains - an OAuth `redirect_uri` that accepts an attacker
host is token/code theft (high), a server-followed redirect can become SSRF, and a redirect off a trusted login
domain is a strong phishing primitive. Evidence = the raw 3xx exchange showing the attacker host in `Location`.

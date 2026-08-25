# Authentication & session testing

**Trigger:** the app has authentication - a login form (`type=password`), a session cookie (`Set-Cookie`), a 401/403, or `/login`/`/signin`/`/oauth`/`/session` endpoints.

**Get a session first.** If credentials are available (`--creds` / `--context`), log in - use `logio` (auth-only agent) to obtain the session, and `prawlio` to crawl the app UNDER that session so the authenticated surface is discovered. Carry the session cookie/token into every check below. Two accounts (`--creds` + `--creds-b`) unlock the cross-account tests.

**Session management:**
- **Cookie flags** - the session cookie must be `HttpOnly`, `Secure`, and `SameSite=Lax/Strict`. Missing `HttpOnly` = JS-stealable (chains with XSS); missing `Secure` = sent over plain HTTP.
- **Logout invalidation** - after logout, replay the OLD cookie/token on a gated endpoint. Still works = the session is not invalidated server-side.
- **Session fixation** - set a known session id before login; if it survives authentication (not rotated), that is fixation.
- **Token entropy** - session ids/tokens that are sequential, timestamped, or short are guessable.
- **Lifetime** - a session/token that never expires or allows unlimited parallel sessions is a weakness (JWT `exp`: see the JWT playbook).

**Auth bypass:**
- **Forced browsing** - request post-auth pages/APIs (`/admin`, `/account`, `/api/...`) with NO session. Data back = broken authentication.
- **Parameter / verb tampering** - `role=admin`, `admin=true`, `?debug=1`, a different HTTP method, or a spoofed `X-Forwarded-For` / `X-Original-URL` / `X-Forwarded-Host` to slip past a gateway.
- **IDOR on identity** - swap your user id/email/token for another's on account endpoints (walk ids like the BOLA play).

**Credential & recovery flows:**
- **Password reset** - is the reset token RETURNED in the response, short/guessable, non-expiring, or reusable? Can you poison the reset link via `Host` / `X-Forwarded-Host` (sends the victim a link to your domain)? Can you reset another user's password by changing an id?
- **Remember-me** - a long-lived token: tied to the device? killed on logout? forgeable (see JWT)?
- **MFA** - after step 1, is the post-MFA endpoint reachable without completing step 2? Is the OTP brute-forceable (no rate-limit), reusable, or leaked in a response?
- **User enumeration** - login/reset/registration that answers differently for a real vs a fake account.

**Confirm + chain:** a session replayable after logout, a forgeable/guessable token, a reset you can trigger for another user, or a forced-browse into gated data is broken authentication - chain it to full account takeover or admin access. Do NOT brute-force or spray real credentials without explicit authorization: it locks accounts and is out of scope for most programs.

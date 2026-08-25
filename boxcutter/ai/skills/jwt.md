# JWT attacks

**Trigger:** a JWT (`eyJ...`) is handed to you - in a Set-Cookie, a response body, an `Authorization: Bearer`, or a parameter.

**Action:** decode the header + payload (base64url) and attack the signature, then replay the forged token:
- **alg:none** - set `"alg":"none"`, drop the signature, keep/raise your claims (`role`/`admin`/`sub`). Accepted = broken verification.
- **RS256 -> HS256 confusion** - if the header is RS256, re-sign with HS256 using the server's PUBLIC key bytes as the HMAC secret. Accepted = key-confusion auth bypass.
- **Weak secret** - HS256 tokens: try common secrets and words derived from the target (domain labels, product name, `secret`/`changeme`/`jwt`). A crack lets you mint ANY token.
- **Unverified signature** - change a claim and resend the ORIGINAL signature; if it still works the server never verifies.
- **`kid` injection** - the header `kid` may be a file path or SQL - try `../../dev/null` (empty key -> forge with "") or an injection payload.
- **Claim tampering** - flip `role`/`isAdmin`/`tenant`/`sub`/`email` and look for horizontal/vertical escalation.

**Confirm:** a token you forged (or one handed to a low-priv/guest user) that unlocks another user's data or an admin/gated endpoint is broken authentication. CHAIN it: forged/elevated token -> victim data / admin console / account takeover.

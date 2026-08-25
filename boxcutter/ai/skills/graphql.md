# GraphQL deep-dive

When the API is GraphQL this IS the whole attack surface - never stop at "introspection enabled".

**Trigger:** graphql-detect found a GraphQL endpoint, a `/graphql` path answers a POST `{"query":"{__typename}"}`, or the SPA bundle points at a single GraphQL URL.

**Action:**
1. `graphql-audit` it (introspection, arg-injection SQLi/SSTI, verbose errors, mutation exposure - it self-confirms these).
2. Then go BEYOND the auto-audit, which ONLY injects no-arg fields and merely DRY-probes mutations: send your OWN `http-request` POSTs of `{"query":"..."}` bodies to `/graphql`, driven by the introspected schema, and reason GENERICALLY about each field by its name, args and return type (never a memorised query name):
   - **Excessive data:** on any field returning a user/account/object type, SELECT the sensitive scalar subfields (`password`, `passwordHash`, `token`, `accessToken`, `apiKey`, `secret`, `email`, `ssn`, `card`). A field that returns another principal's credential/token/PII unauthenticated is excessive-data exposure.
   - **BOLA via args:** any field taking an `id`/`code`/`slug`/`userId`/`orderId`-style arg - pass ids you were NOT given (walk 1,2,3; sequential codes like `GC-00001`; a UUID you saw echoed elsewhere) and select the sensitive subfields. Objects that are not yours coming back = BOLA / broken object-level auth.
   - **Path traversal via args:** any arg named `file`/`path`/`doc`/`name`/`template`/`report` - set it to `../../../../etc/passwd`; file contents back = traversal.
   - **Mutations you MUST execute** (the auto-audit will not - it dry-probes): run the SINGLE-REQUEST ones with real args and read the response. A register/signup that accepts and reflects a `role`/`credits`/`isAdmin` input field = mass-assignment; a requestPasswordReset/forgotPassword that RETURNS the reset token in its response = leaked/weak reset; a loginAs/impersonate/switchUser that mints ANOTHER user's token with no admin check = broken auth (then CHAIN that token); a checkout/refund/transfer that trusts a client `total`/`amount`/negative value = business logic.

**Confirm:** unauth sensitive fields, another principal's object, file contents in a field, a stuck privileged input field, a returned reset token, or a minted foreign token are EACH a separate finding. The `extensions` stack traces on errors are verbose-error disclosure.

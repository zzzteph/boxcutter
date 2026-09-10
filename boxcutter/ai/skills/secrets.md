---
name: secrets
label: Hardcoded / leaked credentials and API keys (JS bundles, responses, git & config artifacts)
triggers: [js-bundle, api-response, dotfile, git-artifact, source-map, config-file, env-leak]
preconditions: []
scope: requests-only
safety: benign
severity_hint: high
---

# Leaked secrets and credentials

## Overview
A live credential, API key, token, or private key is reachable without authorization - baked into a JS bundle,
returned in a response, or left in a `.git`/config/backup artifact. Proof is fetching the artifact and asserting
its body contains the secret pattern; the finding is only real when the value is HIGH-ENTROPY and plausibly live.
Extract ONE value to prove exposure - never harvest en masse, never use the key against third-party services.

## Attack surface
- JS bundles / source maps: `apiKey`, `AKIA...`, `sk_live_`, `ghp_`, `xox[baprs]-`, `AIza`, bearer tokens,
  Firebase config, base64 blobs decoding to creds.
- API responses: tokens/secrets over-serialized into JSON (see info_disclosure), session/reset tokens in bodies.
- Git artifacts: `/.git/config`, `/.git/HEAD`, packed objects, commit history with removed-but-present secrets.
- Config/backup: `.env`, `settings.py`, `application.properties`, `web.config`, `*.bak`, `*.old`, `id_rsa`.

## Hunt methodology
1. Reach for `scan-secrets` first (trufflehog-backed): point it at crawled JS, response bodies, and fetched
   artifacts; it carries the detector DB and entropy checks and flags high-confidence, verifiable hits. Trust
   those over hand-written regex.
2. Feed it breadth: `katana-crawl` + `js-endpoints` for bundles, `path-bust` for dotfiles/backups, `nuclei`
   for known exposure templates. Fetch each candidate with `http-request` and re-scan the body.
3. Classify the hit (provider, live vs test, scope) from its prefix; confirm it is not an obvious placeholder.
4. Stop at one confirmed live secret per source. Do not authenticate to external providers to "verify".

## Checks (predict -> send -> assert)
- technique: secret in JS bundle
  send: fetch a crawled bundle, run `scan-secrets` over the body
  predict: {status_in: [200], body_contains: ["AKIA", "sk_live_", "ghp_", "AIza", "xox"]}   # adapt to detected provider
  refute_if: {body_not_contains: "AKIA"}
  fp_note: match must be high-entropy and live-shaped, not `AKIAEXAMPLE`/`your-key-here`/a public/publishable key.

- technique: secret in API response
  send: request an endpoint and scan the returned body for token/key patterns
  predict: {status_in: [200], body_contains: ["secret", "api_key", "Bearer ", "-----BEGIN"]}
  refute_if: {body_not_contains: "secret"}
  fp_note: a field named `token` holding an empty/opaque session id you already own is not a leak - it must be a
           credential you should not have (another user's, an internal service key).

- technique: exposed .git repository
  send: fetch `/.git/config` then `/.git/HEAD`
  predict: {status_in: [200], body_contains: ["[core]", "ref: refs/heads"]}
  refute_if: {status_in: [403, 404]}
  fp_note: a 200 HTML soft-404 is not the repo - the body must be real git plumbing; then scan objects for secrets.

- technique: config / key file
  send: fetch `/.env`, `/id_rsa`, `/application.properties`, `/config.php.bak`
  predict: {status_in: [200], body_contains: ["-----BEGIN", "PASSWORD=", "SECRET"]}
  refute_if: {status_in: [403, 404]}
  fp_note: confirm the value is real and not a committed sample (`.env.example`); a template file is informational only.

## Notes
Severity: high for a live third-party or internal credential; critical if it grants cloud/admin/prod access or
customer data. Evidence = the source URL and the exact leaked line (redact the middle in the report, keep enough
to prove it). Never call the provider's API with the key or use it against any third party - possession is the proof.

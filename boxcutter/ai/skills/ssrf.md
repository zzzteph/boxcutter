---
name: ssrf
label: Server-side request forgery (SSRF, blind and full-response)
triggers: [url-param, uri, callback, webhook, image, feed, proxy, dest, fetch-from-url, import-link, pdf-render, screenshot, preview]
preconditions: [an out-of-band listener you control for blind proofs]
scope: requests-only
safety: benign
severity_hint: high
---

# Server-side request forgery (SSRF)

## Overview
An endpoint takes a URL or host that the SERVER then fetches, so you can steer that request at targets the
server can reach but you cannot: loopback, internal hosts, cloud metadata. Proof is either an out-of-band hit
arriving at a host you control (blind SSRF) or internal/metadata content reflected in the response (full-
response SSRF). A single 200 to an external URL is expected behaviour, not a finding - the finding is the server
reaching somewhere it should not.

## Attack surface
- Params the server dereferences: `url`, `uri`, `callback`, `webhook`, `image`, `feed`, `proxy`, `dest`.
- Features that fetch on your behalf: "import from link", "fetch from URL", RSS/feed readers, avatar-by-URL.
- Renderers: PDF/screenshot/preview/thumbnail generators that load remote resources.
- Second-order: a stored URL a backend job fetches later, and open redirects the server follows through.

## Hunt methodology
1. From recon, list every request carrying a URL/host value; `api-map` and `js-endpoints` to surface fetchers.
2. Point one param at a UNIQUE out-of-band host you control and watch the listener - any request arriving from
   the target's backend is blind SSRF even with no visible response.
3. Try internal targets: `http://127.0.0.1:<port>`, `http://localhost`, `http://[::1]`,
   `http://169.254.169.254/latest/meta-data/` (cloud metadata), and internal hostnames the app hinted at.
4. Bypass filters: alternate IP encodings (decimal/octal/hex), a redirect you control that 302s to the internal
   target, `http://attacker.com@internal`, a trailing dot, DNS rebinding, or `file://`/`gopher://`/`dict://`.
5. Keep proofs benign: read a metadata index or a version banner, never pivot into the cloud account.

## Checks (predict -> send -> assert)
- technique: blind SSRF via out-of-band callback
  send: set the URL param to a unique host you control, then check your listener
  predict: {}    # not gradeable here - confirm via the out-of-band hit; record as open_proof_gap until observed
  refute_if: {}
  fp_note: only a request actually arriving from the target's backend confirms it; a client-side fetch or your
           own browser hitting the host is not proof.

- technique: full-response SSRF to loopback / internal
  send: set the URL param to `http://127.0.0.1:<port>` or an internal host and read the body
  predict: {status_in: [200], differs_from_control: true}   # control = the same param at an external benign URL
  refute_if: {status_in: [400, 403, 502, 504], body_not_contains: "<internal marker>"}
  fp_note: the body must contain content only the internal service returns (a service banner, an internal page),
           not a generic error or the external control's content.

- technique: cloud metadata read
  send: set the URL param to `http://169.254.169.254/latest/meta-data/`
  predict: {status_in: [200], body_contains: "meta-data"}
  refute_if: {status_in: [400, 403, 404], body_not_contains: "meta-data"}
  fp_note: reflected input is not proof - the index listing must come from the metadata service. Credentials
           reachable here = critical; note the reach, do not exfiltrate.

- technique: filter bypass to an internal target
  send: re-send the internal target via an alternate encoding or an attacker redirect that 302s inward
  predict: {status_in: [200], differs_from_control: true, body_contains: "<internal marker>"}
  refute_if: {status_in: [400, 403]}
  fp_note: confirm the bypass reaches the SAME internal content the direct attempt was blocked from.

## Notes
Severity: high for confirmed internal reach; critical when it reaches cloud metadata credentials or an internal
admin service (chain to the cloud account or an authenticated internal API). Evidence = the out-of-band hit or
the differential exchange (internal target vs external control). Record whether it is blind (callback only) or
full-response, and what the server can reach.

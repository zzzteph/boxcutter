---
name: http_injection
label: HTTP injection (CRLF / header injection, request smuggling CL.TE/TE.CL, web cache poisoning)
triggers: [redirect-param, header-reflection, url-in-param, proxy, cdn, cache, keep-alive, host-header, next-url]
preconditions: [a target fronted by/behind an HTTP intermediary is likely for smuggling & cache poisoning]
scope: requests-only
safety: intrusive
severity_hint: high
---

# HTTP injection (CRLF, header injection, smuggling, cache poisoning)

## Overview
User input crosses a protocol boundary it should not: a `\r\n` breaks into the response headers (CRLF/header
injection), a malformed length/transfer set desyncs a front-end from a back-end (request smuggling), or a
poisoned response gets STORED and served to other users (cache poisoning). Proof is that the SERVER/proxy behaves
at the protocol level differently - an injected header appears in the response, a delayed/desynced reply arrives,
or a marker served back to a fresh victim request. Confirm differentially against a clean control.

## Attack surface
- Reflected-into-header values: redirect/`Location` params, `Set-Cookie` seeds, `next`/`url`/`returnTo`, language
  and CORS-echo values. `js-endpoints` / `katana-crawl` to find them.
- Length/transfer handling: any deployment with a front proxy/CDN/load-balancer + back-end (`CL.TE`, `TE.CL`).
- Cacheable responses keyed loosely: static-ish pages that reflect an unkeyed header/param (`X-Forwarded-Host`,
  `X-Forwarded-Scheme`, extra query params) - the classic cache-poisoning gadget.

## Hunt methodology
1. Reflection first: with `http-request`/`fuzz`, put CR/LF-encoded payloads into params/headers that land in the
   response, and watch whether an injected header/cookie materialises. `nuclei` templates cover common CRLF gadgets.
2. Cache poisoning: send an unkeyed header (`X-Forwarded-Host: evil`) with a cache-buster query; if it reflects
   and the response is cacheable, re-request WITHOUT the header and see if the poisoned value is served back.
3. Smuggling: intrusive and deployment-specific - probe CL.TE/TE.CL with timing-differential requests; treat as a
   careful, last-resort test.
4. Intrusive class: smuggling and poisoning can affect OTHER users. Use unique benign markers, buster params, and
   your own paths; never persist a payload that harms real traffic, and flush/expire what you can.

## Checks (predict -> send -> assert)
- technique: CRLF / header injection
  send: inject `%0d%0aInjected-Header:%20boxcutter` into a param/header reflected into the response
  predict: {status_in: [200, 301, 302], header_contains: "Injected-Header"}
  refute_if: {body_contains: "%0d%0a"}
  fp_note: the payload must land as a REAL response header (header_contains), not URL-encoded in the body; if the
           server strips/encodes CR/LF, it is not vulnerable.

- technique: open-redirect via header injection
  send: set the redirect param to `//boxcutter.example` or a CRLF-forged `Location`
  predict: {status_in: [301, 302, 307], header_contains: "boxcutter.example"}
  refute_if: {header_contains: "<the original trusted host>"}
  fp_note: confirm `Location` points off-origin; a same-site redirect that merely echoes the path is not it.

- technique: unkeyed-header cache poisoning
  send: request with `X-Forwarded-Host: boxcutter.evil` + a unique cache-buster, then re-request WITHOUT it
  predict: {body_contains: "boxcutter.evil", header_contains: "hit", differs_from_control: true}
  refute_if: {body_not_contains: "boxcutter.evil"}
  fp_note: the poison must be SERVED to the clean follow-up (cache hit on the buster key); reflection alone,
           without a cached second serve, is only header reflection. control = clean request pre-poison.

- technique: request smuggling (CL.TE / TE.CL)
  send: a crafted request with conflicting Content-Length vs Transfer-Encoding to desync front/back-end
  predict: {latency_ms_gte: 4500, differs_from_control: true}   # timing-differential desync probe
  refute_if: {latency_ms_lt: 1500}
  fp_note: highly deployment-specific and easy to false-positive on jitter; a timing delta is a LEAD - full proof
           (a smuggled request surfacing in another response) is often ungradeable here, record as open_proof_gap
           until a captured desynced response confirms it. Never smuggle payloads that hit other users.

## Notes
Severity: high for exploitable CRLF/open-redirect and confirmed cache poisoning; critical for working request
smuggling (it hijacks other users' requests). Evidence = the injected header/Location in the response, or the
poisoned value served to a clean control request. This class touches shared infrastructure - keep markers unique
and benign, and prefer reflection/redirect proofs over live smuggling unless scope explicitly allows it.

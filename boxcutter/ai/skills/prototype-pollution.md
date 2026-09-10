---
name: prototype-pollution
label: JavaScript prototype pollution (to a gadget)
triggers: [json-merge, query-param, nested-object-body, config-param, __proto__, constructor-prototype]
preconditions: []
scope: requests-only
safety: benign
severity_hint: high
---

# JavaScript prototype pollution

## Overview
A Node/JS backend deep-merges or path-assigns attacker-controlled keys (`__proto__`, `constructor.prototype`)
into an object, poisoning `Object.prototype` so an injected property appears on objects the app never set. The
finding needs a GADGET: prove a polluted property changes server behavior in a harness-measurable way, not just
that the merge was accepted. A polluted property that never reflects is an open_proof_gap.

## Attack surface
- JSON bodies that get deep-merged into config/options (`{"__proto__":{"x":"1337"}}`).
- Query/body path params: `?__proto__[x]=1337`, `?constructor[prototype][x]=1337`, `a[__proto__][x]=1337`.
- Settings/profile/import endpoints that recursively assign nested keys.
Map inputs with `katana-crawl`, `js-endpoints`, `api-map`, `swagger-specs`; confirm the stack is Node/JS first.

## Hunt methodology
1. Identify endpoints that accept nested objects and likely merge them (settings, import, bulk update).
2. Run `fuzz` with `{FUZZ}` on a nested key; its DB includes `__proto__`/prototype payloads and self-confirms.
   Reproduce with `http-request`, sending the raw JSON body form.
3. Pollute with a property the app will later READ into a response, then request an endpoint that would echo a
   default/missing value - if it now returns your injected value, the gadget is proven. Keep values benign
   (a marker string); never pollute keys that would break the service or execute code.

## Checks (predict -> send -> assert)
- technique: reflected-property gadget (JSON merge)
  send: POST `{"__proto__":{"pp_marker":"1337"}}` to a merge endpoint, then GET an object that omits `pp_marker`
  predict: {status_in: [200], body_contains: "1337", differs_from_control: true}
  refute_if: {body_not_contains: "1337"}
  fp_note: the marker must surface on an object that never defined it (proving prototype reach), not merely be
           echoed back by the same request; control = the pre-pollution GET.

- technique: query-param path pollution
  send: `?__proto__[pp_marker]=1337` (and `?constructor[prototype][pp_marker]=1337`), then read a defaulted field
  predict: {status_in: [200], body_contains: "1337", differs_from_control: true}
  refute_if: {body_not_contains: "1337"}
  fp_note: if the value only appears inside the same object you set, that is normal assignment - the proof is it
           leaking onto a DIFFERENT response object.

- technique: behavior-flip gadget (no reflection)
  send: pollute a known library gadget key that alters a code path (e.g. a boolean option) vs a clean control
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {differs_from_control: false}
  fp_note: the two responses must differ because of the polluted default; a flaky diff is not proof - re-fire.

- technique: pollution accepted but no observable gadget
  send: a `__proto__` payload the server ingests without erroring
  predict: {}    # merge acceptance alone is NOT gradeable impact - record as open_proof_gap until a gadget is observed
  fp_note: acceptance is a lead only; the finding requires a measurable behavior/reflection change.

## Notes
Severity: high when a gadget changes auth/logic or reaches RCE via a known library sink; low/informational if only
the merge is accepted with no gadget. Evidence = the injected property surfacing on an unrelated object, or the
behavior-flip pair. Keep markers benign and avoid keys that could crash the process.

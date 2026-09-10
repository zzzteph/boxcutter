---
name: ssti
label: Server-side template injection (SSTI)
triggers: [name-into-page, subject/message-field, label/greeting, email-template, profile-render, reflected-into-server-html]
preconditions: []
scope: requests-only
safety: benign
severity_hint: critical
---

# Server-side template injection (SSTI)

## Overview
User input reaches a server-side template engine (Jinja2, Twig, Freemarker, Velocity, Smarty, Thymeleaf, Mako)
and is rendered as template code, not data. Prove it by making the ENGINE evaluate an expression the app never
wrote - a deterministic arithmetic marker measured against a benign control. A reflection that echoes the literal
is XSS surface, not SSTI; the finding is the computed product appearing in the response.

## Attack surface
Any input reflected into a server-rendered page or email: names, subjects, messages, labels, greetings, profile
fields, error/notification text, and templated exports. Map candidates with `katana-crawl`, `js-endpoints`,
`api-map`, `swagger-specs`; `nuclei` can flag known template-engine exposures on a fingerprinted stack.

## Hunt methodology
1. Find every input that lands in server-rendered output; note the likely engine from stack fingerprints.
2. Run `fuzz` with `{FUZZ}` on one such field - its DB carries the cross-engine math probes and it does the
   two-shot product confirmation automatically. Reproduce confirmed hits with `http-request`.
3. Send a math probe unique to templates (not plain HTML) and confirm the PRODUCT, not the literal. Use a random
   operand pair each time so a coincidental page number never fools you. Identify the engine from which syntax
   evaluates, then note the escalation path (engine-specific gadget) without running a destructive command.

## Checks (predict -> send -> assert)
- technique: cross-engine arithmetic probe
  send: `${7*191}`, `{{7*191}}`, `#{7*191}`, `<%= 7*191 %>` (one per engine) into the field
  predict: {status_in: [200], body_contains: "1337", differs_from_control: true}
  refute_if: {body_not_contains: "1337"}
  fp_note: `1337` must be COMPUTED; if the response instead shows the literal `7*191` it is reflection/XSS, not SSTI.

- technique: randomized re-confirm
  send: a second distinct pair, e.g. `{{13*17}}` -> expect `221`
  predict: {status_in: [200], body_contains: "221", differs_from_control: true}
  refute_if: {body_not_contains: "221"}
  fp_note: the number must change with the operands - a static `1337`/`49` on the page is a coincidence, not eval.

- technique: engine fingerprint by syntax divergence
  send: probes that evaluate in one engine but not another (e.g. Twig `{{7*'7'}}` -> `49` vs Jinja `{{7*'7'}}` -> `7777777`)
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {differs_from_control: false}
  fp_note: use the divergent output to name the engine; do not claim an engine on a single ambiguous product.

- technique: escalation to code execution
  send: the engine-specific gadget (Jinja `{{config.__class__...}}`/`cycler`, Twig `_self`, Freemarker `Execute`) - benign read only
  predict: {}    # command-exec markers vary per engine - grade via the RCE skill's computed-marker check; record as open_proof_gap until observed
  fp_note: only a benign read-only marker (a version string, an arithmetic echo) - never a destructive command.

## Notes
Severity: critical when SSTI reaches OS command execution; high for confirmed server-side evaluation with limited
reach. Evidence = the computed-product exchange (probe vs control), plus the randomized re-confirm. A confirmed
SSTI is the start - identify the engine and note the exec path, but keep every proof benign.

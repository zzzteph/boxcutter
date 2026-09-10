---
name: business_logic
label: Business-logic abuse (workflow, state, ownership, payment, price/quantity tampering)
triggers: [checkout, cart, price-field, quantity-field, coupon, multi-step-flow, state-param, order-status, wallet]
preconditions: [an authenticated identity, and a normal end-to-end run of the flow captured as a baseline]
scope: requests-only
safety: benign
severity_hint: high
---

# Business-logic abuse

## Overview
The request is well-formed and authorized, but the app trusts a value or an ORDER of operations it should
compute or enforce itself: a price the client sends, a quantity that goes negative, a coupon applied twice, a
workflow step skipped, a state advanced out of turn. The bug is proven by making the SERVER accept an outcome it
should reject - a total that undercharges, a resource granted without payment, a step reached without its
prerequisite. Always compare against the honest baseline you captured first.

## Attack surface
- Client-supplied money/amounts: `price`, `amount`, `total`, `currency`, `discount`, `shipping` in a cart/order body.
- Quantities: negative, zero, fractional, or huge `qty`/`count` (negative qty can credit a wallet).
- Coupons/credits: reuse, stacking, applying after checkout, self-referral.
- Workflow state: `status`/`step`/`stage` fields, or endpoints that assume a prior call (pay -> ship, verify -> activate).
- Ownership/actor fields: `owner`, `seller_id`, `from_account` the client can set.

## Hunt methodology
1. Run the flow once, honestly, with `http-request`; save every request/response as the baseline. `api-map` and
   `swagger-specs` to enumerate the state-changing endpoints and required params.
2. Identify each value the SERVER should own (price, totals, actor, status) but the CLIENT sends.
3. Replay one step at a time with a single tampered value; compare the accepted result to the baseline.
4. Test the sequence: call a later step without its prerequisite, or repeat a one-shot step (coupon, redeem).
5. Keep proofs benign - a $0.01 order, a duplicated free coupon, a read-only status you should not reach. Never
   place real paid orders or drain balances.

## Checks (predict -> send -> assert)
- technique: price / total tampering
  send: replay the create-order/checkout call with `price` or `total` lowered (e.g. 999 -> 1)
  predict: {status_in: [200, 201], body_contains: "1", differs_from_control: true}   # control = honest baseline
  refute_if: {status_in: [400, 409, 422]}
  fp_note: the tampered value must be REFLECTED IN THE SERVER'S STORED order/total, not just echoed in the request;
           re-fetch the order and confirm the persisted amount changed.

- technique: negative / zero quantity
  send: set `qty` to a negative or zero value on add-to-cart / order
  predict: {status_in: [200, 201], differs_from_control: true}
  refute_if: {status_in: [400, 422]}
  fp_note: confirm the effect is real - a negative qty that lowers the total or credits a balance, not a UI-only
           echo the server later clamps to 0.

- technique: coupon / credit reuse or stacking
  send: apply the same one-time coupon twice, or stack two exclusive codes in one order
  predict: {status_in: [200], body_not_contains: "already", differs_from_control: true}
  refute_if: {body_contains: ["already used", "invalid", "expired"]}
  fp_note: the discount must actually COMPOUND on the server total; a 200 that silently ignores the second code
           is not a finding.

- technique: step-skipping / out-of-order state
  send: call a late step directly (e.g. mark-shipped, activate, download) without its prerequisite call
  predict: {status_in: [200, 201], differs_from_control: true, control_status_in: [400, 403, 409]}
  refute_if: {status_in: [400, 403, 409]}
  fp_note: control = the same call attempted before the prerequisite in a clean session; the finding is that the
           server let you reach the state without the gate, not merely a 200.

- technique: actor / ownership override
  send: set an actor field (`seller_id`, `from_account`, `owner`) to a value that is not you
  predict: {status_in: [200, 201], body_contains: "<the injected actor>", differs_from_control: true}
  refute_if: {status_in: [400, 403]}
  fp_note: overlaps IDOR/privesc - here the point is the server ACTS AS the injected actor; confirm the stored
           record attributes the action to them, not to you.

## Notes
Severity: high when it yields money, free goods, or an unauthorized state change; critical if it scales (bulk
free orders, arbitrary balance credit). Evidence = the honest baseline exchange paired with the tampered one that
the server accepted, plus a re-fetch showing the bad state persisted. Logic bugs are app-specific: read the flow,
then break the assumption it forgot to enforce.

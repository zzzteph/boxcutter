---
name: race_condition
label: Race conditions (TOCTOU, double-spend, limit bypass via parallel requests)
triggers: [redeem, withdraw, transfer, coupon, one-time, quota, limit, balance, apply, claim, vote]
preconditions: [an authenticated identity, and an action with a server-side limit or single-use guarantee]
scope: requests-only
safety: intrusive
severity_hint: high
---

# Race conditions (TOCTOU)

## Overview
Between the moment the server CHECKS a condition and the moment it ACTS on it, a parallel request slips through:
a coupon meant to be used once is redeemed twice, a balance is spent past zero, a "max 1 per user" limit yields
several. The proof is a burst of concurrent identical requests producing MORE successful outcomes than the limit
allows - an effect a single request could never achieve. Confirm the surplus persisted on the server, not just
that N requests returned 200.

## Attack surface
- Single-use tokens/coupons/invites, one-time gift-card or credit redemptions.
- Balance/quota spends: withdraw, transfer, purchase against a limited balance or stock.
- "One per account" actions: vote, claim, apply-referral, rate, follow.
- Any check-then-write with no DB constraint / row lock / idempotency key behind it.

## Hunt methodology
1. Establish the guarantee honestly first: run the action once with `http-request`, confirm the second attempt is
   refused (used/insufficient/limit reached). That refusal is your control.
2. Craft the exact single request that performs the action (method, path, body, session/token).
3. Fire N copies concurrently (a tight parallel burst, same instant). Count how many SUCCEEDED and re-read the
   server state (balance, redemption count, stock).
4. Intrusive by nature: it mutates real state and can double-spend - keep N small (5-20), use only values/objects
   YOU own, and never race another user's data or push a balance to a harmful negative. Restore/refund if you can.

## Checks (predict -> send -> assert)
- technique: single-use token double-redeem
  send: fire the same one-time redeem/claim request ~10x concurrently
  predict: {status_in: [200], differs_from_control: true, control_status_in: [400, 409]}
  refute_if: {control_status_in: [200]}
  fp_note: control = the SECOND sequential redeem, which must be refused; the finding is >1 concurrent success.
           Re-read the redemption count on the server - two 200s but one recorded use is not a race.

- technique: balance / quota overspend
  send: submit several concurrent spends that each fit the balance but together exceed it
  predict: {status_in: [200], differs_from_control: true}
  refute_if: {status_in: [400, 409, 422]}
  fp_note: confirm the resulting server balance went NEGATIVE or below the floor; a single accepted spend within
           balance is not proof.

- technique: per-user limit bypass
  send: fire N concurrent copies of a "max 1 per account" action (vote/claim/apply)
  predict: {status_in: [200], differs_from_control: true, control_status_in: [409, 429, 403]}
  refute_if: {control_status_in: [200]}
  fp_note: re-read the count of recorded actions - the finding is the stored count exceeding the cap, not the raw
           number of 200 responses (some may be idempotent no-ops).

- technique: TOCTOU state flip
  send: race a state-mutating call against the check that guards it (e.g. cancel while it finalizes)
  predict: {differs_from_control: true}
  refute_if: {differs_from_control: false}
  fp_note: the observable must be an inconsistent end state (both applied, or applied-and-refunded); if timing is
           not gradeable from status/latency alone, record as open_proof_gap until the surplus state is observed.

## Notes
Severity: high for double-spend / limit bypass with real value; critical if it scales to material loss. Evidence
= the control refusal of the second sequential attempt, plus the concurrent burst showing multiple successes AND
the persisted surplus (count/balance) on re-read. This is the one intrusive play here - keep the burst small,
scoped to your own objects, and reverse the effect where possible.

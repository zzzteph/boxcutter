# vera - a planning, hypothesis-driven scanner (design)

Working name: `vera` (placeholder, verification-themed, fits the bob/caleb/travis/irvin
naming). Rename before build if you prefer.

## 1. What it is

A new standalone boxcutter agent, a peer to bob and caleb. It drives the raw boxcutter
tools itself (it does NOT call bob/caleb/travis). What makes it different from bob is its
architecture, not its tool access:

1. It authors a **plan** and revises it as it learns.
2. It records **hypotheses** as explicit objects, each with a prediction that can be checked.
3. It **loads skills** on demand instead of only on deterministic signals.
4. It treats **validation as the gate**: a claim is not a finding until a separate step
   reproduces its prediction from captured HTTP.

Scope: same bug classes bob and caleb target (authz/IDOR, injection, exposure, auth), over
HTTP only (requests-only, consistent with the rest of boxcutter). Single target per run,
like the other agents.

## 2. Why it is not bob

bob is a single fast pass where the model reasons in its head and emits a report at the end.
Its "CONFIRM" discipline is model self-attestation, its reasoning is only visible under
`--debug` and truncated, and it has no independent validation step. vera moves the thinking
out of the model's head and into logged actions, and it makes reproduction (not self-report)
the thing that promotes a claim to a finding.

## 3. Core idea: thinking is an action

The model's plan, its hypotheses, and its decision to load a skill are all **tool calls**,
not hidden chain-of-thought. The harness logs every one. That gives two things at once:

- A durable, structured, always-on record of what vera thinks and why (no `--debug` needed).
- The plan/hypothesis/validation machinery, because those are just tools the model calls.

## 4. The action catalog

vera hands the model one tool list built from two groups.

**Real actions** (the boxcutter tools, via `toolschema.native_tools`, dispatched with
`toolschema.to_argv` then the shared `_call`, exactly as bob does):
`http-request`, `katana-crawl`, `js-endpoints`, `path-bust`, `api-map`, `fuzz`, `sqlmap`,
`nuclei`, `graphql-detect`, `swagger-specs`, `harvest`, and the rest of bob's allowlist.
Read-only and non-destructive, same guardrails as bob (`_call` refuses anything off the list;
never PUT/PATCH/DELETE; stay on host).

**Meta-actions** (implemented by the harness, not boxcutter subcommands):

- `build_plan(steps)` - set or replace the current plan. `steps` is an ordered list of
  `{action, target?, why, expects?}`. Returns the stored plan with ids.
- `add_hypothesis(h)` - record a hypothesis (schema in section 5). Returns its id.
- `load_skill(name)` - pull a playbook body into the system prompt for later turns. Unknown
  name returns the catalog so the model can pick a valid one.
- `validate_hypothesis(id, checks, as_identity, control_identity)` - run the test as one
  identity and the control as another, then decide the verdict (sections 7 and 5b).

Real HTTP actions carry an optional `as_identity` (default: the primary authenticated identity);
the harness attaches that identity's session and captures any new `Set-Cookie`/token back into
it. The harness knows which group a call belongs to by name, dispatches accordingly, and appends
every call and result to the run log.

## 5. Artifacts

A small in-memory store (fresh and minimal; do not reuse caleb's heavier store), serialized
to the reasoning/output dir at the end.

**Plan**: `{steps: [{id, action, target, why, expects, status: todo|done|dropped}], round}`.

**Hypothesis**:

```
{
  id,
  claim,                # one line: what is wrong
  vuln_class,           # BOLA | BFLA | missing-authn | SQLi | SSRF | exposure | ...
  rationale,            # why vera suspects it, from what it observed
  predicted_observable, # a CHECKABLE predicate (section 7), stated BEFORE the test
  control,              # the comparison request that should NOT succeed
  test_plan,            # the concrete requests to run
  status,               # proposed | testing | confirmed | refuted | inconclusive
  tier,                 # machine-checked | model-judged   (set at validation)
  evidence: [exchange], # captured request/response pairs
  fp_checks,            # why this is not a soft-404 / reflected-not-executed / CSRF-field / etc.
}
```

**Evidence exchange**: `{request: {method, url, headers, body}, response: {status, headers, body_excerpt}}`.
Captured automatically for every real-action HTTP call so it is always replayable without the model.

**Identity**: `{label, kind: anon|creds|token, headers, cookies, token, login: {url, method, body, extract}, alive}`.
`anon` is always present (the no-auth control). Others are added when vera authenticates; `alive`
is set only when that identity's auth hypothesis validates (section 5b), so it is proven, not assumed.

## 5b. Sessions and identities

Authentication is not optional for vera: the validation gate (section 7) proves access-control
bugs by comparison, which needs at least an authenticated identity plus a control. So vera
carries a small identity/session layer, reusing boxcutter's existing primitives rather than
rebuilding caleb's multi-identity phase engine.

- **Take auth in.** Credentials, a cookie, or a bearer header supplied via `--context` or
  `--header` are parsed (bob's `briefing.parse`) into a `creds`/`token` identity at startup.
- **Login is a hypothesis, not a mechanical step.** When vera observes a login surface, it does
  not silently authenticate. It records an auth hypothesis, for example claim "POST /login with
  the supplied creds establishes an authenticated session", `predicted_observable`
  `{sets_session: true, then: {request: "GET /account", status_in: [200], differs_from_control: true,
    control_status_in: [401, 403]}}`. It then tests it: send the login through `http-request`
  (the harness captures the `Set-Cookie`/token into a candidate identity via bob's
  `_parse_set_cookie` / jar), then probe a known-gated endpoint as that identity and as `anon`.
  The identity is marked `alive` only if that hypothesis validates. A refuted login (wrong
  creds, unexpected flow) stays in the log and tells vera to try another approach. Every login
  attempt is therefore visible, and "am I actually logged in" is proven, never assumed.
- **Stay logged in.** Once an identity is `alive`, its cookie/token jar is attached to every
  subsequent request made as that identity, so the session persists across the whole run.
- **Re-auth on expiry.** When a request as an `alive` identity comes back 401 or is redirected
  to login, the harness marks the session dead and re-runs the auth hypothesis once (replay the
  login, re-prove with a gated request). Same mechanism as the first login, not a special path.
- **Identities feed validation.** Every real action and every `validate_hypothesis` names the
  identity to run as (default: the primary authenticated one). Controls run as `anon` or a
  second identity, which is what makes both the auth proof above and differential BOLA/BFLA
  proofs possible with one mechanism.

Scope note: vera handles the common cases (form/JSON login, cookie or bearer session, one
re-auth on expiry, an optional second identity passed in). Deep identity ACQUISITION (weak-secret
JWT forge, alg:none, debug-token grab, refresh-token flows, register-then-login chains) stays
caleb's job; vera borrows the session plumbing, not the acquisition battery.

## 6. The loop

Bounded, plan-driven, with replanning capped like caleb's `--max-rounds`.

1. **Recon** - a few cheap real actions (http-request on base, a light crawl, tech probe).
2. **build_plan** - author the first plan from what recon showed.
3. **add_hypothesis** - one object per suspicion, each with a predicted observable and a control.
4. **Execute** - work the plan with real actions; `load_skill` when a surface appears that
   has a playbook (deterministic signal auto-loads too, section 8).
5. **validate_hypothesis** - for each hypothesis, run its test, capture the exchange, decide
   the verdict from the prediction, set tier + evidence.
6. **Replan** - on material new observations, revise the plan and add hypotheses. Bounded by
   `--max-rounds`; also bounded by `--max-steps` overall (like bob).
7. **Report** - emit only confirmed findings (plus candidates at a lower tier if asked), each
   with its evidence.

## 7. The validation gate (the important part)

This is where the value concentrates. Rules:

- **The prediction is stated before the test.** `predicted_observable` is a small structured
  predicate the harness can evaluate, for example:
  `{status_in: [200], body_contains: "<nonce-or-marker>", differs_from_control: true,
    control_status_in: [401, 403]}`.
  The model authors the predicate; the harness enforces it. This is how we get an independent
  oracle without a dumb fixed rule-set (the thing that made bob's old backstops produce junk):
  the check is specific to this hypothesis and written by the model, but graded by code.
- **Differential by default.** For access-control classes the strong proof is the attacker
  request succeeding while the `control` (run as the `anon` identity, or as a second principal)
  is denied. The harness runs the same request as each identity and compares; "the body
  differs" must be a real diff it computes, not a model assertion. This is why the identity
  layer (section 5b) is a prerequisite for the gate, not an add-on.
- **Two tiers, never collapsed.** If the prediction is expressible as a predicate the harness
  can check, the verdict is `machine-checked`. If the outcome needs the model to read an
  ambiguous body, it is `model-judged` and recorded as such. machine-checked outranks
  model-judged everywhere.
- **Falsify, do not confirm.** Each hypothesis must also carry what would prove it wrong (the
  control, and any `NOT` condition), and the harness checks that too. A refuted hypothesis is
  kept in the log as refuted, not deleted.
- **Evidence is the exchange.** Because every HTTP call is captured, a confirmed finding ships
  with the exact requests and responses that prove it. This is boxcutter's analog of a PoC
  bundle, at zero extra cost.

Promotion rule: a hypothesis reaches the report as **confirmed** only with a passing
machine-checked validation. A `model-judged` pass ships as **candidate**. Everything else
(refuted, inconclusive) stays in the log and never ships as a finding.

## 8. Skill loading

Two paths, kept together:

- **Deterministic (kept):** the existing `ai/skills.py` signal loading still applies. When the
  tools observe a surface (graphql-detect finds an endpoint), its playbook auto-loads. Same
  reproducibility property as today.
- **Model-requested (new):** vera also shows the model a **catalog** (skill names plus a
  one-line description each, not the bodies) and lets it `load_skill(name)` when it decides a
  playbook is relevant before a signal fires. Every load is logged.

Trade: model-requested loading gives up byte-for-byte reproducibility but keeps auditability
(the log shows exactly which skills loaded and why). Acceptable for an exploratory hunter.
The loadable set is the `ai/skills.py` playbook registry, not the packaging skills under the
repo-root `skills/`.

## 9. Output

- **Run log** (always on): the ordered stream of plan revisions, hypotheses with predictions,
  skill loads, tool calls, and validation verdicts. Written to `--reasoning-dir` style output,
  and summarized to stderr live. This is the "show me what it thinks" deliverable.
- **Report**: confirmed findings first, each with claim, class, impact, the evidence exchange,
  and remediation. Candidates (model-judged) in a separate section. Refuted/inconclusive
  hypotheses listed briefly so the reader sees what was ruled out.
- **Envelope**: findings returned through `output_result` in the standard boxcutter finding
  shape, so `--table`, `--json`, `--severity` all work like every other tool.

## 10. Integration with existing plumbing

vera is a standard agent module: `NAME = "vera"`, `add_arguments(parser)`, `run(args) -> int`,
auto-registered in the AI list in `cli.py` (same as bob/caleb).

- LLM: `provider.make_provider(...)`, then the `provider.send / parse / assistant_msg /
  tool_results` loop, exactly as bob.
- Tools: `toolschema.native_tools(_TOOLS)` for the real actions, plus the meta-action schemas
  appended to the same list. Dispatch by name.
- Skills: `skills.for_signals(...)` for deterministic loads; a new `skills.catalog()` and
  `skills.body(name)` for the model-requested path.
- Reasoning: reuse `provider.set_reasoning_context(...)` and `add_agent_args` so `--reasoning`,
  `--reasoning-dir`, `--max-steps`, `--context`, `--provider/--model/--api-key/--base-url` all
  behave as they do for the other agents.
- Guardrails: the same `_call` allowlist and header handling as bob (parse `--context` auth,
  never touch third-party hosts, read-only methods).

CLI shape:

```
boxcutter vera https://app.example.com --provider litellm --model openai/gpt-5 --api-key ... \
  --context "auth: Cookie: session=abc" --max-rounds 3 --reasoning-dir ./vera_run --report vera.md
```

## 11. Decision points (recommended defaults in bold)

1. **Replan cadence**: **bounded replanning** (replan on material new observations, capped by
   `--max-rounds`, default 3). Not plan-once (too rigid), not replan-every-step (loop-prone).
2. **Validation strictness for the report**: **hard gate**. confirmed = machine-checked only;
   model-judged = candidate; nothing else ships as a finding.
3. **Store**: **fresh minimal store** in vera, not caleb's artifact store (keeps the new tool
   lean and independent).
4. **Skill loading**: **hybrid** (deterministic signals plus model-requested from a catalog),
   all loads logged.
5. **Scope of real actions**: **bob's allowlist** as the starting catalog (read-only,
   non-destructive), trimmed if any prove noisy.

## 12. Non-goals

- Not a conductor over bob/caleb/travis (it does not call other agents).
- No runtime source instrumentation (requests-only; validation ceiling is "observable over
  HTTP", which covers the target bug classes).
- Not a replacement for bob or caleb; a third option with a different method.

## 13. Open questions

- Concurrency: run validations sequentially first; consider bounded parallel HTTP later.
- Nonce injection: for `body_contains` checks, prefer a value vera controls (a unique marker
  in a request) over matching attacker-uncontrolled strings, to avoid echo false positives.
- Severity: derive from class plus confirmed impact, or let the model propose and the gate
  cap it. Leaning: model proposes, report caps unverified at candidate.

---

# Addenda (folded in after the comparative study of strix/pentagi/PentestGPT/pentestagent/shannon and the bugbounty-monitor skills)

## 14. Borrowed refinements (Tier 1, adopted)

From the five-repo study. Only the validation-discipline ideas are taken; the agent-swarm
topologies and heavy deps are not.

- **Three-state closure with a proof-gap default** (from strix). A hypothesis resolves to
  `confirmed`, `ruled_out`, or `open_proof_gap` - never silently dropped. If a candidate is
  neither proven nor specifically ruled out, it defaults to `open_proof_gap` and is reported as
  such. This replaces the earlier `confirmed | refuted | inconclusive` wording.
- **Coverage ledger reconciled before finishing** (from strix). vera records every surface it
  touched (endpoint/param/identity), including clean ones, and must reconcile the ledger before
  it may finish. This kills the silent-omission failure that pure hypothesis loops suffer: the
  report can state what was checked and found safe, not just what was found broken.
- **Loop / repetition detector** (from pentagi). The harness counts identical and total tool
  calls; crossing a threshold forces a re-plan instead of spinning. boxcutter's bob already has
  the primitive (refuse the same exact call after 2 repeats); vera elevates it to a governor
  that triggers replanning.
- **Findings and hypotheses exist only via a tool call, never chat text** (from strix + shannon).
  A claim in prose is not a record. vera terminates only via an explicit finish action, and a
  finding is real only when it was created through `add_hypothesis` + a passing
  `validate_hypothesis`. "The model said it is authenticated / vulnerable" can never count.
- **Auth as a validated step is confirmed correct** (from shannon's `validate-authentication`).
  No change; external validation of section 5b.

Tier 2 (planned, not blocking the first build): a parse/condense pass between raw HTTP and the
planner (PentestGPT), a planner/generator split on top of the hunter/validator split
(PentestGPT), belief-aware finding fields (assumptions, counterevidence, confidence rationale,
severity-change conditions), and hypothesis dedup before spending validation budget (shannon).

## 15. Traffic and evidence store

vera captures traffic in two layers; the store it produces is the evidence corpus the
validation gate reads from and the replayable PoC the report ships.

- **Layer 1 (default, no new deps): in-process capture in `core/http`.** Every request/response
  vera makes directly, and every boxcutter-native (python `requests`) tool call, is recorded to
  a per-run traffic store keyed by target/run. This is always on and is the source the harness
  reads when it checks a predicted observable.
- **Layer 2 (optional flag): `mitmdump` sidecar.** External binary tools (sqlmap, nuclei,
  katana, httpx) run as separate processes whose traffic never reaches `core/http`. When full
  capture is wanted, vera launches `mitmdump`, points those tools at it via `HTTP(S)_PROXY` plus
  its CA, and an addon appends every flow to the same store. Free, headless, python; not a
  default because it adds a dependency and TLS-MITM setup. (ZAP, already bundled, can serve the
  same role if adding mitmproxy is unwanted.)

Every evidence exchange (section 5) points into this store, so a confirmed finding always ships
with the exact requests/responses that prove it, replayable without the model.

## 16. Skill seeding, generation, and the global store

Seed source is the author's own `bugbounty-monitor/skills` corpus (28 markdown playbooks,
license-clean), adapted - not the external repos (licensing + harness-fit + injection risk).

Four tiers:

1. **Seed (ships with vera).** ~18-20 requests-only skills ported from bugbounty-monitor:
   authn (with jwt split out), idor, privesc, business_logic, race_condition, sqli, rce,
   injection, http_injection, ssrf, xxe, lfi, xss, csrf, cors, open_redirect, deserialization,
   info_disclosure, secrets, crypto. Plus ~6-7 new dedicated skills the corpus lacks: ssti, jwt,
   file-upload, graphql, swagger/openapi, nosql-injection, prototype-pollution. Native/host/CI
   content (memory corruption, most of tls/supply_chain, mobile) is dropped as out of scope for
   requests-only; dos is kept but safety-gated. `bughunter.md` + `misc.md` become vera's meta /
   idea-seed layer (prioritization, cross-category chains), not per-vuln skills.
2. **Within-run.** vera derives target-specific hypothesis templates and reuses them across
   rounds (run store, ephemeral).
3. **Global generated (quarantine).** Skills vera drafts accumulate in a global store with
   provenance (target/run/commit), treated as untrusted data, never auto-loaded.
4. **Global trusted.** Seed + promoted skills; the only tier that auto-loads. Promotion from
   quarantine is validation-earned (the skill's hypotheses validated on N real targets) with a
   review flag you can veto.

### Skill file format (the port target)

Each skill is markdown with agent-control frontmatter, replacing bugbounty-monitor's bounty
metadata:

```
---
name: ssrf
triggers: [url-param, webhook, import-by-url, pdf-render, image-fetch]
preconditions: []
scope: requests-only
safety: benign            # benign | intrusive | destructive-never
severity_hint: high
---
```

Body sections, trimmed from the 12-section bounty format to what an agent needs:
Overview, Attack surface, Hunt methodology, and the core primitive -

**Checks (predict -> send -> assert).** The single most important adaptation: each technique is
written as a committed contract, not loose criteria. Generalize bugbounty-monitor's
"Verification & impact / confirmed vs false-positive" pairs (the SQLi per-technique table is the
model) into:

```
- technique: blind time-based SQLi
  send: inject a sleep(5) payload into ONE param of a realistic request
  predict: {latency_ms_gte: 4500, differs_from_control: true}     # control = un-delayed payload
  refute_if: {latency_ms_lt: 1500}                                # fast response => not it
  fp_note: a uniformly slow endpoint; re-fire to confirm the delay tracks the payload
```

The Triage/Reporting/Bounty-intelligence sections are dropped to save prompt budget; a one-line
severity hint lives in frontmatter.

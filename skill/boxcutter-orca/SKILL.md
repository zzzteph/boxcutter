---
name: boxcutter-orca
description: >-
  Use this skill to run a multi-agent security scan of a web application or API. Boxcutter Orca is the
  agent-based sibling of boxcutter-pentest: an orchestrator dispatches boxcutter-only area agents
  (auth, recon, exposure, injection, access, api, report) and they converge on the same findings report (bugs + suggestions).
  Triggers include "run boxcutter-orca", "orca scan", "multi-agent pentest", "parallel security scan",
  "security scan", "pentest", "bug bounty", "hunt for bugs", "scan this", "check for vulnerabilities", or any
  request to test a URL/host/API for security issues with parallel agents. Application-layer only — does not
  test authenticated login/OAuth/MFA flows, SSRF/CSRF/open-redirect, stateful multi-step logic, or
  environment/infrastructure (ports, subdomain takeover, CORS); those are out of scope for this tool.
license: MIT
compatibility: Needs a subagent-capable runtime (e.g. Claude Code Task tool); agents run boxcutter via a shell/exec tool.
metadata:
  version: "0.3.0"
  owner: boxcutter
  author: boxcutter
  category: security
  tags: [security, pentest, dast, web, api, multi-agent, boxcutter]
  requires: container runtime (podman|docker) + image ghcr.io/zzzteph/boxcutter:latest
  agents: auth, recon, exposure, injection, access, api, report
  tool-policy: boxcutter sub-commands only — enforce at the runtime with an allowlist like Bash(docker:*), Bash(podman:*)
---

# Boxcutter Orca

> Boxcutter Orca is the **multi-agent** web/API security scanner for authorized pentest & bug-bounty work. Where boxcutter-pentest walks one
> linear 11-step plan, Orca splits the same work across an **orchestrator → 6 area agents** so independent
> surfaces are assessed in parallel. Every agent scans **only** with the **boxcutter** container
> (https://github.com/zzzteph/boxcutter) and drives individual **tools** for precision; they converge on the
> **identical report** — same STATUS lines, same FINDINGS/COVERAGE contract (carried inline by `report-agent`).
>
> Same discipline as boxcutter-pentest: a tool's output is *signal, not a conclusion.* Confirm every finding by
> hand before flagging it. **Confirm, never exploit.**

## How Orca differs from boxcutter-pentest

| | boxcutter-pentest | boxcutter-orca |
|---|---|---|
| Shape | one linear 11-step plan | orchestrator → 6 area agents (one level) |
| Concurrency | sequential | recon first, then exposure/injection/access/api in **parallel** |
| Engine | boxcutter only | boxcutter only (identical) |
| Report | single contract | **the same** contract (inline in `report-agent`) |
| Runtime | LLM-agnostic | needs a runtime with **subagents** (Claude Code Task tool) |

Use Orca when your runtime supports subagents and you want parallel coverage; use boxcutter-pentest for a
single-agent, fully portable run. They are interchangeable in output.

## Prerequisites

A container runtime — **Podman** (preferred) or **Docker** — with the boxcutter image, and a runtime that can
spawn subagents. Pull once:

```sh
{RUNTIME} pull ghcr.io/zzzteph/boxcutter:latest
```

`{RUNTIME}` = `podman` or `docker`. Always reference the image by its full name `ghcr.io/zzzteph/boxcutter:latest`.

> **One-level nesting.** The orchestrator (this skill, the main session) spawns the area agents directly —
> agents **do not** spawn further agents. Each area agent both plans its slice *and* runs boxcutter itself.

## Tool Usage — STRICT (applies to every agent)

**Every agent may only invoke boxcutter sub-commands via the container runtime. No agent may write or run any
other code.** Same contract boxcutter-pentest enforces; it binds the orchestrator and all six area agents.

**Precision — tools over workflows.** Agents drive individual boxcutter **tools** (`httpx`, `katana-crawl`,
`dirsearch`, `nuclei`, `fuzz`, `scan-secrets`, `http-request`, `swagger-endpoints`, `graphql-audit`, …) for
exact, attributable, one-target-at-a-time control — a precise tool call is easy to confirm, attribute to an
agent, and reproduce. Workflows (`web-*`, `swagger-scan`, `graphql-scan`, …) are **optional accelerators** for
breadth — reach for one only to cover a large surface fast, never as the default.

FORBIDDEN for every agent: inline Python / heredocs; piping tool output (`| jq`, `| grep`, `| python`); host
tools (`curl`, `wget`, `nmap`, PowerShell, `sed`/`awk`/`grep` on output); helper scripts to parse JSON;
`boxcutter raw <binary>` (unless explicitly instructed); any tool outside the boxcutter catalog.

Never issue PUT/PATCH/DELETE. Redact secret/credential/PII values (pattern + location only). **Confirm, do
not exploit.** Authorization is the user's responsibility — boxcutter is for authorized testing only.

## Layers & gates

The six agents fall in three layers with structured hand-offs — **Planning → Execution → Analysis**:

- **Planning** — the **orchestrator** (this skill) + `auth-agent`: capture & validate the shared session,
  resolve entry point, run the gates, dispatch the execution agents, aggregate.
- **Execution** — `recon-agent` (runs first; produces the surface), then `exposure-agent`, `injection-agent`,
  `access-agent`, `api-agent` in **parallel** (each consumes the recon surface).
- **Analysis** — `report-agent`: confirm, classify, dedup, and write the single report.

Three gates keep it honest:
- **Pre-flight gate** (after recon) — `recon-agent` must return a live host/surface. If nothing serves HTTP,
  **skip the parallel phase** and have `report-agent` report no live target (nothing to scan). Don't burn a
  parallel burst on a dead host.
- **Confirmation gate** (in `report-agent`) — a candidate becomes `[VULN]` only if Step 6 confirmation
  produces verbatim evidence; otherwise downgrade to `[SUGGESTION]` or omit.
- **Coverage gate** (in `report-agent`) — a step whose tools fail is noted in `COVERAGE` (never a finding),
  and the `COVERAGE` line is always included so the report shows exactly what was and wasn't tested.

## Orchestration

1. **Resolve entry point + auth.** Pick the entry shape and record any `--header` auth to pass to **every**
   agent. The shape routes the work to **tools**; a workflow is only an optional breadth accelerator:

   | User provides | What agents drive (tools) | Optional accelerator |
   |---|---|---|
   | Domain / host (no scheme) | `httpx` → `katana-crawl`/`dirsearch` → `nuclei`/`fuzz`/`http-request` | `web-full` |
   | URL (has scheme) | `katana-crawl` → `nuclei`/`fuzz`/`http-request` | `web-scan` |
   | API endpoints | `fuzz` + `http-request` per URL | `web-dast` |
   | OpenAPI/Swagger spec | `swagger-endpoints --fuzzable` → `fuzz`; `http-request` | `swagger-scan` |

2. **Banner**: output `boxcutter-orca v{version}`.
3. **Phase 0 — auth.** Dispatch `auth-agent` to capture + validate the Cookie/Authorization header(s) (and a
   2nd identity for access testing). **Share the returned `--header` set(s) with every agent below** — the
   session is defined once, here.
4. **Phase 1 — recon.** Dispatch `recon-agent` (shared headers, entry shape, depth, runtime). It returns the
   surface (live URLs, param URLs, JS, paths, spec/GraphQL hints) and its STATUS lines. **Apply the pre-flight gate.**
5. **Phase 2 — parallel execution.** Dispatch `exposure-agent`, `injection-agent`, `access-agent`,
   `api-agent` **in parallel**, each fed the **ranked** recon surface (test **Tier 1 first**; skip Tier 3
   under a time budget — no shotgun fuzzing) + shared headers + depth. Each returns candidate findings
   (unconfirmed) and its STATUS line(s).
6. **Phase 3 — analysis.** Dispatch `report-agent` with all candidates + every agent's STATUS lines. It runs
   the confirmation + coverage gates and writes the report.

Each agent owns specific phases and emits their status lines, so the assembled report matches
`report-agent`'s template exactly:

| Area agent | Layer | Phases it owns |
|---|---|---|
| `auth-agent` | Planning (Phase 0) | Auth (shared session) |
| `recon-agent` | Execution (feeds Planning) | Setup, Recon, Crawl, Content |
| `exposure-agent` | Execution | Exposures, Secrets, Visual |
| `injection-agent` | Execution | Injection |
| `access-agent` | Execution | Access |
| `api-agent` | Execution | Injection (swagger/GraphQL share) |
| `report-agent` | Analysis | Confirm, Report |

A step that does not apply (entry point / Fast mode / no inputs) is still emitted as `SKIPPED` — never
dropped — exactly as in boxcutter-pentest.

## The report (identical contract)

`report-agent` is the **single writer** — it carries the full report template and the classification
cheatsheet **inline** (no shared file to load). It emits the `boxcutter-orca v{version}` banner, the ten Step
STATUS lines (collated from the agents), FINDINGS (Reproduce + Evidence), COVERAGE, and SUMMARY, dedups by
`(title, url)`, and classifies each finding — output indistinguishable from a boxcutter-pentest report. Optional artifacts (`--output`/`--jsonl`/`--dump` into a mounted dir) are
produced by whichever agent runs the tool — pure boxcutter.

## Self-contained agents

There is **no shared `references/` folder** — a spawned subagent runs in its own context and can't reliably
load one. Each agent carries what it needs **inline**: its commands, flags, STATUS line, and what to flag;
`report-agent` additionally carries the report template + classification. The one thing passed at
runtime is the shared **session** (auth headers) — captured once by `auth-agent`, propagated by the orchestrator.

## Agents

Defined in `agents/` — each is one self-contained area agent that **plans its slice and runs boxcutter
itself** (no sub-spawning). Tools-first; workflows only as accelerators.

- `auth-agent` — Phase 0; captures + validates the Cookie/Authorization session, shares it with all agents
- `recon-agent` — Setup/Recon/Crawl/Content; returns the surface (and the pre-flight signal)
- `exposure-agent` — Exposures/Secrets/Visual
- `injection-agent` — Injection
- `access-agent` — Access
- `api-agent` — Injection (swagger + GraphQL)
- `report-agent` — Confirm + Report (single writer; runs the confirmation & coverage gates)

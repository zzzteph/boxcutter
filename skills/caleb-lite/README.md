# caleb-lite — a Claude Code skill (single-pass web vuln check over the boxcutter Docker image)

A lightweight, **"flat"** cousin of boxcutter's `caleb` agent, **with Claude as the brain**. Given one target URL/host,
Claude drives boxcutter's standard scanners (path-bust, fuzz, nuclei, sqlmap-to-confirm, scan-secrets) plus plain GETs,
reads what they return, and writes a prioritised findings report with fixes. It does the **detection** half of caleb and
deliberately skips the offensive machinery.

## What's here
- `SKILL.md` — the skill (the instructions Claude follows) — the Claude-driven, interactive path.
- `_run.sh` + `_report.py` — a **non-interactive** runner: `bash _run.sh https://target` drives the whole detection
  sequence (fetch → path-bust → nuclei → scan-secrets → fuzz each observed param → screenshot) and writes
  `/tmp/caleb-lite/<host>/report.md` plus the raw `*.json`. Zero prompts.

## Prerequisites
- The `boxcutter` Docker image built: `docker build -t boxcutter .` (from the boxcutter repo root).
- Docker runnable (this repo's env needs `sudo docker`).

## Use it
**As a Claude Code slash command** — symlinked into `.claude/skills/`, so just:
```
/caleb-lite https://target.example
```
(or "basic web check https://target.example", "quick vuln scan of target.example, no lateral movement").

**Portable** — copy this `caleb-lite/` folder into any repo's `.claude/skills/` (or symlink it) to enable the command
there. Nothing outside this folder is required beyond the boxcutter image.

## Scope — what it DOES and does NOT do
**Does:** fingerprint the app · audit security headers & cookie flags · detect exposed files/dirs (`.git`, `.env`,
backups, listings) · sweep params with `fuzz` and **confirm** a suspected SQLi with `sqlmap` · run `nuclei`'s
non-intrusive detection templates · flag leaked secrets · screenshot for context · report findings with fixes.

**Does NOT (this is what keeps it "lite"):** no login / auth-bypass / identity acquisition / token forging or replay ·
no admin or privilege-escalation · **no lateral movement or credential reuse** · no chaining a finding into the next
exploit (no SQLi→dump→login→RCE) · no destructive writes (PUT/PATCH/DELETE) · no data exfiltration (an exposed
`.git`/`.env`/secret is reported by its presence, not dumped). Single-pass, unauthenticated, non-destructive.

Authorization for its targets is treated as already granted, so caleb-lite runs **fully autonomously and never
prompts** — no permission/confirmation/clarification questions. Point it at a target you're authorized to test and it
drives the whole check to a report on its own.

## Relationship to boxcutter `caleb`
| | boxcutter `ai caleb` | this skill (`caleb-lite`) |
|---|---|---|
| brain | OpenAI (gpt-5 family) | **Claude** (this console) |
| tools | in-process boxcutter | **boxcutter Docker image** |
| identities / auth | acquires, forges, re-auths | **none** — unauthenticated only |
| lateral movement / chaining | BFLA, lateral reuse, →RCE | **none** — detect + confirm, then stop |
| depth | multi-phase, multi-identity, exploit chains | **single-pass**, non-destructive check |
| best for | full authorized engagement in a lab | a quick hygiene/vuln check on one target |

Same toolbox, same "Claude drives boxcutter tools" pattern as the `travis-recon` skill (recon) — `caleb-lite` is the
safe, single-pass **checking** counterpart. For deep authenticated / lateral / chained testing, use the full `caleb`
agent against a target you're authorized to attack.

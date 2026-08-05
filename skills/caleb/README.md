# caleb (Claude Code skill)

Multi-phase, multi-identity authenticated web pentest over the boxcutter image, the Claude-driven twin of the
boxcutter `ai caleb` agent. Claude is the brain; the boxcutter image gives it the tools. caleb recons the surface,
acquires identities, re-scans the authenticated surface per identity, chains a foothold into the next hop
(SQLi → creds → login → sink → RCE), tests one account against another (two-account BOLA/BFLA), re-auths mid-run, and
loops back on a new lead. It stays agnostic: it discovers the app's real endpoints and never hardcodes a target path.

For pure recon over many domains use the `travis-recon` skill; for a quick unauthenticated hygiene check, that is a
single pass (bob's lane). caleb is the deep, authorized engagement.

## What's here
- `SKILL.md`: the skill (the multi-phase methodology Claude follows). This is the whole thing.

## Prerequisites
- Docker or Podman.
- The published boxcutter image (no local build):
  ```
  BOX="${BOX:-docker}"        # or BOX=podman; root-only docker: BOX='sudo docker'
  $BOX pull ghcr.io/zzzteph/boxcutter:latest
  ```

## Use it
As a Claude Code slash command (symlinked into `.claude/skills/`):
```
/caleb https://target.example
```
(or "deep authenticated pentest of target.example", "chain the findings on target.example (authorized)"). Give it
seed creds when you have them; two accounts unlock the cross-account tests.

Portable: copy this `caleb/` folder into any repo's `.claude/skills/` (or symlink it). Nothing outside this folder is
required beyond the boxcutter image.

## Authorization
caleb is offensive: it authenticates, chains exploits, and proves impact up to RCE. Run it only against a target you
are authorized to attack. Authorization for the target is treated as already granted, so it runs autonomously and
never prompts. Secret values are redacted in the report.

## Relationship to boxcutter `ai caleb`
| | boxcutter `ai caleb` | this skill (`caleb`) |
|---|---|---|
| brain | OpenAI (gpt-5 family) | Claude (this console) |
| tools | in-process boxcutter | boxcutter image (docker/podman) |
| phases | P0 recon → P1 identity → P2 authed → P3 chain → P4 review/loop | same, Claude-driven |
| identities | acquires, forges, re-auths | same (register/login/forge, two accounts) |
| chaining | BFLA, lateral reuse, → RCE | same (drive `http-request` as the pivot) |
| best for | headless / batch runs | interactive deep testing in Claude Code |

Same mission and phase model as `ai caleb`, with Claude as the brain instead of an OpenAI loop.

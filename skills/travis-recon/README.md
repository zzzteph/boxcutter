# travis-recon — a Claude Code skill (subdomain recon over the boxcutter Docker image)

A self-contained skill that reproduces boxcutter's `travis` discovery agent **with Claude as the brain** instead of
travis's internal OpenAI loop. Given a root domain, Claude uses the **boxcutter Docker image** for the deterministic
tools (subfinder, wayback, dnsx, httpx, http-request, screenshot) and supplies the intelligence itself — infer the
naming scheme, invent + verify clever mutations, probe the promising hosts, rank them (Critical/High/Medium/Low),
and **screenshot every Critical + High host** as evidence. Output: a prioritised "explore first" list of live
subdomains plus the shots. **Pure recon — no vuln testing.**

## What's here
- `SKILL.md` — the skill (instructions Claude follows). This is the whole thing.

## Prerequisites
- The `boxcutter` Docker image built: `docker build -t boxcutter .` (from the boxcutter repo root).
- Docker runnable (this repo's env needs `sudo docker`).

## Use it
**As a Claude Code slash command** — it's symlinked into `.claude/skills/`, so just:
```
/travis-recon amsterdam.nl
```
(or say "recon this domain: amsterdam.nl" / "map the attack surface of amsterdam.nl").

**Portable** — copy this `travis-recon/` folder into any repo's `.claude/skills/` (or symlink it) to enable the same
command there. Nothing outside this folder is required beyond the boxcutter image.

**Manually** — the fast path the skill uses is one deterministic command (no API key), then Claude reasons on top:
```
sudo docker run --rm boxcutter ai travis <domain> --discover --triage-top 0 --mut-cap 2000 > seed.json 2>seed.log
```
`seed.json .data[]` = live hosts; Claude then infers the scheme, expands with `dnsx`, probes with `http-request`/
`screenshot`, and produces the ranked report.

## Relationship to boxcutter `travis`
| | boxcutter `ai travis --discover` | this skill |
|---|---|---|
| brain | OpenAI (gpt-5-mini best) | **Claude** (this console) |
| tools | in-process boxcutter | **boxcutter Docker image** |
| deterministic seed | built-in | reuses `travis --triage-top 0` |
| best for | headless / batch runs | interactive recon in Claude Code |

Same mission, same ranking rubric (incl. the tailoring: O365/cloud records → Low, parked ≠ gated, Dutch env tokens,
org-local env prefixes like DUO's `vt-`), **plus a Critical tier and mandatory screenshots of every Critical/High host.**

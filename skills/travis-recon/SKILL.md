---
name: travis-recon
description: Agentic subdomain recon on a domain using the boxcutter Docker image as the toolbox, with Claude as the brain (like the boxcutter `travis` agent, but Claude-driven, no OpenAI key). Given a root domain it discovers live subdomains, cleverly expands them, ranks them (Critical/High/Medium/Low), and SCREENSHOTS every Critical + High host as evidence, producing a PRIORITISED "explore first" list. Pure recon — no vuln testing. Trigger on "travis-recon <domain>", "recon this domain", "discover subdomains of X", "map the attack surface of X", or when the user wants a ranked live-host list for a domain.
---

# travis-recon — Claude-driven subdomain discovery over the boxcutter Docker image

You act as **travis**: turn a root domain into a **ranked list of live subdomains to explore first**, with a
**screenshot of every Critical and High host**. The boxcutter Docker image gives you the deterministic tools; YOU
supply the intelligence (infer the naming scheme, invent + verify clever mutations, probe the promising hosts, rank
by confirmed content, capture the visual evidence). **Pure recon** — never test for a vuln, never brute a path
wordlist, never send anything but GET/OPTIONS. Stay on the target's own domain.

## Setup (do this first)
- Pull the published image (no local build needed); it runs on docker or podman:
  ```
  IMG="${BOXCUTTER_IMAGE:-ghcr.io/zzzteph/boxcutter:latest}"
  BOX="${BOX:-docker}"          # or BOX=podman; for a root-only docker use BOX='sudo docker'
  $BOX pull "$IMG"
  ```
  Set `BOX` and `IMG` once and reuse them in every command below (`$BOX run --rm "$IMG" …`).
- Work in a scratch dir so files land somewhere known: `mkdir -p /tmp/travis-recon/<domain> && cd /tmp/travis-recon/<domain>`. (For a batch, use a stable per-domain dir like `/home/steph/rijks/<domain>/`.)
- Every tool prints a JSON envelope `{"success":..., "data":[...], ...}` to stdout. Parse `data`.

## Step 1 — deterministic SEED (one command, no API key)
Run boxcutter's own pipeline in **deterministic mode** (`--triage-top 0` = no LLM, no key), which does
subfinder + wayback + dnsx brute/resolve + wildcard-filter + parallel HTTP alive-check.

**Timing (measured on a 4-core Pi): small microsites ~2 min, large agencies ~5 min. It WILL exceed the default 2-min
Bash timeout.** Run it with a long timeout, or backgrounded + poll:
```
# option A: long timeout (Bash tool: set timeout to ~540000 ms)
$BOX run --rm "$IMG" ai travis <DOMAIN> --discover --triage-top 0 --mut-cap 2000 > seed.json 2>seed.log
# option B: background + poll seed.json for a `"success"` envelope
```
`seed.json` `.data[]` = live hosts, each `{host, url, status, title, server, interest, class, why}` (the seed already
assigns a deterministic `interest` of High/Medium/Low — you REFINE it); `.stats` has `live`/`resolving`/`candidates`/
`mutations_tried`. NOTE: no `scheme` field in this mode — you infer the scheme yourself in Step 2. If `.data` is empty,
check `seed.log` (dead domain, or the image/docker isn't runnable).

## Step 2 — infer the SCHEME (your reasoning)
Read the live hostnames. What conventions does THIS org use? env tokens (dev/tst/test/acc/**acceptatie**/ont/
**ontwikkel**/staging/preprod/prod — Dutch orgs favour acc/acceptatie/ont/tst), service words (api/admin/portal/vpn/
git/**mijn**/…), numbering (app1/2), sub-zone nesting (`x.acc.example` vs `x.prod.example`), team/region prefixes.
State the pattern.

**Org-local env markers the generic wordlist misses (learned from the rijksoverheid corpus — look for these):**
- a **short prefix that shadows a prod host** is an environment: DUO runs `vt-mijn`, `vt-zakelijk`, `vt-digidzakelijk`
  beside the prod `mijn`/`zakelijk` → `vt-` is their test env. When you see `X` and `<pfx>-X` / `<pfx>.X` as a pair,
  `<pfx>` is an env token — chase it across every service.
- `intern` / `-intern` / `inter` = internal (RDW's `act-intern` beside `act`); treat as High even though it is not in
  the stock env list.
- random alphanumeric suffixes (`apk-handboek-oe6eduhgwvm`, `…-a1b2c3`) are **ephemeral cloud/preview hostnames** —
  judge them by content, not the pretty name; often 403-gated.

## Step 3 — EXPAND cleverly (the value you add over the seed)
Derive HIGH-VALUE candidate names FROM the observed scheme — the seed's blind permutation misses org-specific ones
(saw `checker.example` and `x-preprod.example`? try `checker-preprod`, `checker-acc`; saw `api.acc`? try `api.test`,
`api.ont`, `api.prod`; inferred a `vt-`/`acc-` env prefix? splice it onto every prod service you saw). Chase the
INTERESTING families hardest (admin/dev/test/acc/ont/internal/api/vpn/git/mijn). On a shared **government cloud
platform** (a `*.rijkscloud.nl`-style zone) expect whole FAMILIES of devops/identity hosts under nested per-tenant/
per-env labels — `git.<tenant>`, `gitlab.<tenant>`, `keycloak.<env>.<tenant>`, `kibana-ext.<tenant>` — so enumerate
the platform words (gitlab/git/keycloak/grafana/kibana/vault/minio) across every tenant + env label you observe.
VERIFY each candidate resolves before trusting it:

```
# ONE candidate:
$BOX run --rm "$IMG" dnsx <candidate.DOMAIN>            # .data non-empty -> it resolves
# MANY candidates - dnsx --list reads a file that must be INSIDE the container, so MOUNT it with -v:
printf '%s\n' cand1.DOMAIN cand2.DOMAIN cand3.DOMAIN > cands.txt
$BOX run --rm -v "$PWD/cands.txt:/c.txt" "$IMG" dnsx --list /c.txt   # .data = the ones that resolved
```

A candidate that resolves AND answers HTTP (Step 4) is a find the passive tools missed — call it out.

## Step 4 — PROBE the promising, ambiguous ones (judge from content, not the name)
Your PRIMARY probe is `http-request` (text — enough to classify most hosts):
```
$BOX run --rm "$IMG" http-request https://<host>/               # status, title, server, body
```
Probe the interesting few, not all 500 — `http-request` is enough to *classify* most hosts. (Screenshots come in
Step 6, where they are mandatory for the ones you rank Critical/High.)

## Step 5 — RANK (Critical / High / Medium / Low / Skip)
Rate every live host. Rank from CONFIRMED content (status + title + what a screenshot shows), never the name alone.

**Judge STATUS + CONTENT first — the hostname only *elevates* a host that actually serves its own page:**
- **404 / 5xx**, or a **soft-404** (a 200 whose title is `404 / Not Found / Forbidden / Toegang geblokkeerd / maintenance`) → **Low**, however juicy the name (`accounts-uat.example.nl` returning 404 is Low, not High).
- **Off-domain redirect** — the host merely forwards to a *different registrable domain* (e.g. `x-internal.acc.example.nl` → `www.rivm.nl`) → **Low**: the interesting name is a red herring; rank the *target*, not the source. (Same-domain redirects are fine.)
- **401 / 403** → rate by WHAT is gated, read from the **title**, not the hostname: a title showing a real product/console (Keycloak/GitLab/…, or admin/console/beheer) → High; a real named app → Medium; a default/parked/"Forbidden" gate → **Low** (a `phpmyadmin.` host serving a default-403 is NOT a phpMyAdmin).
- Only a host returning **200 with its own real content** earns the name-based tier — a `test.`/`acc.`/`internal.` env host is High *only when it actually serves a real app*.

- **Critical** — a **reachable (HTTP 200) dangerous surface** you can see without auth: an open devops/CI dashboard
  (gitlab/jenkins/grafana/kibana/argocd/rancher/prometheus/harbor/nexus/vault/sonar/gitea), an admin console /
  Spring-Boot `/actuator` serving content, an exposed DB UI (phpmyadmin/adminer), a wide-open Swagger/GraphQL/OpenAPI
  on an internal API, a directory listing or exposed `.git`. Critical = *likely an actual finding a pentester acts on
  now*. (If the same surface is **gated 401/403**, it is High, not Critical — it is protected.)
  - **CONFIRM Critical from the screenshot, not the hostname** — two false-positive classes dominate the rijks corpus:
    (a) **wildcard / parked catch-alls**: a zone where *every* name resolves, so `gitlab.x`, `kibana.x`, `admin.x` all
    serve the same **hosting panel / marketing page** (Plesk, "Hosting.NL – domeinnaam geregistreerd", the org's own
    homepage). Tell = a title shared across many sibling subdomains, or a hosting-panel/parked title → it is **Low**,
    not a GitLab. (b) **public "Dashboard" sites**: the apex/`www` of a site literally titled "Dashboard <topic>"
    (open-data portals) is public info, not an exposed console. Real consoles are on a *sub*domain and show the actual
    product UI ("Keycloak Administration Console", "Explore groups · GitLab", "MinIO Console", "Grafana").
- **High** — non-prod env (dev/test/acc/acceptatie/ont/ontwikkel/staging/preprod, and org-local prefixes like `vt-`),
  admin/console/internal/intranet, VPN, identity/SSO/ADFS, a devops tool that is present but **gated**, an exposed
  app/API worth a deep look.
- **Medium** — an API/login/citizen-portal that is gated or unclear; a 401/403 that gates a REAL named app.
- **Low** — marketing/public site, redirect-to-www, parked/CDN/404 (even if it 403s), AND **standard cloud/O365
  records every tenant has** (`autodiscover`, `enterpriseenrollment`, `enterpriseregistration`, `msoid`,
  `lyncdiscover`, `sip`, `autoconfig`, `_dmarc`/`_domainkey`) — universal noise, never above Low.
- **Skip** — dead (no DNS / no HTTP).

## Step 6 — SCREENSHOT every Critical + High host (MANDATORY evidence)
For **each** host you ranked **Critical or High**, capture a screenshot — it both documents the exposure and confirms
the call (an "admin"-named host that is really a login page, a "staging" that is really parked). Save the PNGs under
`<domain>/shots/` and **Read** each one (the Read tool renders images) to verify before you finalise the rank.

Robust method — drive chromium headless straight to a file (the built-in `screenshot` tool caps httpx at 30s
internally, which is too tight for a cold chromium start on a constrained host):
```
mkdir -p shots
$BOX run --rm -v "$PWD/shots:/shots" --entrypoint chromium "$IMG" \
  --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage --hide-scrollbars \
  --window-size=1366,900 --virtual-time-budget=9000 --timeout=25000 \
  --screenshot=/shots/<host>.png https://<host>/
# then: Read shots/<host>.png     (harmless Vulkan/GL "errors" in the log still produce a valid PNG)
```
Fallback (base64 via the boxcutter tool, fine on a fast host): `$BOX run --rm "$IMG" screenshot https://<host>/`
returns a base64 PNG in `.data[0].image` — decode it to a file, then Read it:
```
$BOX run --rm "$IMG" screenshot https://<host>/ \
  | python3 -c "import sys,json,base64; d=(json.load(sys.stdin).get('data') or [{}])[0]; open('shots/x.png','wb').write(base64.b64decode(d.get('image') or ''))"
```

## Step 7 — REPORT
Output a short markdown report:
- the inferred scheme (incl. any org-local env prefix you found);
- a table sorted **Critical → High → Medium → Low** with `interest | host | status | class | why` (the *why* from
  confirmed content or the scheme; mark which hosts YOU found by mutation);
- for each Critical/High row, reference its screenshot file and one line on what it shows;
- a one-line "explore first" list of the Critical/High/Medium URLs to hand to a scanner or an engineer.

## Guardrails
Recon only. Never run fuzz/sqlmap/nuclei/path-bust or send non-GET methods; a screenshot is a GET render, nothing more.
Redact any secret you happen to see. If a `dnsx` on a few random junk names resolves, the zone is wildcard — trust
HTTP content (distinct title/body), not the mere DNS answer.

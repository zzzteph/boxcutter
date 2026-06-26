<p align="center">
  <img src="logo.png" alt="boxcutter" width="200">
</p>

# boxcutter

**A pentesting toolkit in one container.**

ProjectDiscovery, OWASP ZAP, sqlmap, dirb, dirsearch and a set of Python
recon/fuzz tools behind one CLI. Point it at a URL, host, or domain and it runs
the whole scan — quiet by default, one clean JSON result on stdout, so it drops
straight into a shell, a CI job, or an agent loop.

## Contents

- [Install](#install)
- [Scan](#scan)
- [Options](#options)
- [Tools](#tools)
  - [Recon](#recon)
  - [Crawl](#crawl)
  - [Vulnerability scanners](#vulnerability-scanners)
  - [Fuzzing](#fuzzing)
  - [Secrets / source](#secrets--source)
  - [API specs](#api-specs)
  - [GraphQL](#graphql)
  - [Generic](#generic)
- [Workflows](#workflows)
  - [Authenticated scanning](#authenticated-scanning)
  - [Scanning an OpenAPI / Swagger spec](#scanning-an-openapi--swagger-spec)
  - [Define your own (YAML)](#define-your-own-yaml)
- [AI agent (bob)](#ai-agent-bob)
  - [Run bob](#run-bob)
  - [Models & providers](#models--providers)
  - [Orchestration](#orchestration)
- [Output & dependencies](#output--dependencies)
- [Example run](#example-run)
- [Credits](#credits)

## Install

Requires Docker. Pull the image and tag it `boxcutter` so commands stay short:

```bash
docker pull ghcr.io/zzzteph/boxcutter:latest    
docker tag  ghcr.io/zzzteph/boxcutter:latest boxcutter
# or Docker Hub: 
docker pull zzzteph/boxcutter


docker run --rm boxcutter --list        # list the bundled tools
```

No services to start — one command in, one JSON result out. For brevity, the rest
of this README writes `boxcutter <args>` for `docker run --rm boxcutter <args>`.

## Scan

Point a workflow at a target. The `workflow` keyword is optional — a bare name
resolves to a tool first, then a workflow. New here? `boxcutter web-full <url>`
is the whole scan; everything below is for finer control.

> ⚠️ **These are active, intrusive scans** (sqlmap, ZAP active scan, nuclei-dast,
> fuzzing). Only run them against targets you own or are explicitly authorized to
> test — `web-full` is loud and can trip WAFs, rate limits, or bug-bounty rules.

```bash
# full DAST (active vulnerability scan) of one site; --table prints a readable table
# (crawl -> nuclei -> ZAP -> per-param bundle + swagger + graphql + secrets)
boxcutter web-full https://example.com --steps --table

# only critical/high findings
boxcutter web-full https://example.com --severity critical,high --table

# lighter single-tool variants of the web scan
boxcutter web-fuzz   https://example.com      # fuzz only
boxcutter web-sqlmap https://example.com      # sqlmap only

# one parameterised URL - the reusable per-URL bundle (fuzz + nuclei-dast + sqlmap + zap)
boxcutter endpoint-scan "https://example.com/product?id=1"

# an API: point at a spec URL or a bare host
boxcutter swagger-scan https://api.example.com/openapi.json

# start from a domain: resolving subdomains, then scan the whole environment
boxcutter recon example.com
boxcutter env-scan example.com --steps

# behind auth - the header propagates to every inner tool
boxcutter web-full https://example.com --header "Authorization: Bearer TOKEN"
```

See [Example run](#example-run) for what the findings table looks like.
`boxcutter --list` shows every tool; `boxcutter workflow --list` shows every workflow.

## Options

| Option | Where | What it does |
|---|---|---|
| `--output FILE` | all | save the result to FILE as a readable table |
| `--jsonl FILE` | all | also save the data to FILE as JSON Lines (one record per line) — machine-readable |
| `--table` | all | print a readable text table on stdout instead of JSON |
| `--debug` | all | print progress/diagnostics to stderr |
| `--severity LEVELS` | findings tools + workflows | only report findings at these severities, e.g. `--severity critical,high`; omit to report all |
| `--timeout N` | most tools | per-tool time budget in seconds (defaults vary) |
| `--opt-args "..."` | binary wrappers | extra flags passed straight to the underlying binary |
| `--js` / `--params` | crawlers, wayback | keep only JS URLs / only URLs with query params |
| `--method` / `--data` | fuzz, path-fuzz | HTTP method / POST body to fuzz |
| `--header "K: V"` | most tools + workflows | extra request header; in a workflow it propagates to every inner tool (repeatable) |
| `--wordlist PATH` | dirb | custom wordlist |
| `--base-url URL` | js-endpoints, swagger-parser | base used to resolve discovered paths |
| `--steps` | workflows | print each step as it runs (otherwise silent) |
| `--show-findings` | workflows | stream each finding to stderr as the step that found it ends (live view; pairs with `--steps`, honours `--severity`) |
| `--dump FILE` | workflows | write the full state (every saved step var: live, urls, params, findings, …) to FILE as one JSON object — for analysis |
| `--arg TOOL="..."` | workflows | append args to an inner tool, e.g. `--arg fuzz="--timeout 60"` |

`boxcutter <tool|workflow> --help` shows the exact options for any command.

## Tools

Every tool also takes `--output FILE`, `--debug`, `--table` (see [Options](#options));
the `kind` column is the envelope kind it emits.

### Recon

| Tool | Arguments | kind | What it does |
|---|---|---|---|
| `subfinder <domain>` | — | urls | passive subdomain enumeration: the starting attack surface |
| `dnsx <host>` | `--timeout` | urls | resolve A/AAAA/CNAME — confirms a host is real before you touch it |
| `httpx <host\|url>` | `--timeout` `--opt-args` `--header` | items | which hosts actually serve HTTP(S) (port, scheme, IP) |
| `screenshot <url>` | `--opt-args` `--header` | items | headless screenshot (base64 PNG) + title for fast visual triage |
| `wayback <domain>` | `--js` `--params` `--inc-subdomains` `--timeout` | urls | historical URLs (Wayback/CommonCrawl/OTX/URLScan) — free endpoints + params |
| `wayback-domains <domain>` | `--timeout` | urls | unique hosts seen across those archives |

```bash
boxcutter subfinder example.com                  # passive subdomains
boxcutter dnsx api.example.com                    # does it resolve?
boxcutter httpx example.com --table               # live HTTP services
boxcutter screenshot https://example.com          # base64 PNG + title
boxcutter wayback example.com --params            # archived URLs that have params
boxcutter wayback-domains example.com             # archived hostnames
```

### Crawl

| Tool | Arguments | kind | What it does |
|---|---|---|---|
| `katana-crawl <url>` | `--js` `--params` `--timeout` `--opt-args` `--header` | urls | active crawl of a site with Katana |
| `zap-crawl <url>` | `--js` `--params` `--timeout` `--header` | urls | ZAP spider + AJAX spider (reaches JS-rendered links) |
| `js-endpoints <js-url>` | `--base-url` | items | pull API endpoint references out of a JS file |

> Katana + ZAP merged and deduped — the crawl you usually want — is the
> `web-crawl` workflow (`boxcutter web-crawl <url>`); the scan workflows use it as
> their crawl step.

```bash
boxcutter katana-crawl https://example.com
boxcutter workflow web-crawl https://example.com
boxcutter js-endpoints https://example.com/app.js
```

### Vulnerability scanners

| Tool | Arguments | kind | What it does |
|---|---|---|---|
| `nuclei <url>` | `--opt-args` `--header` | findings | template-based scan (CVEs, misconfig, exposures) |
| `sqlmap <url>` | `--opt-args` `--header` | findings | confirm + exploit SQL injection |
| `dirb <url>` | `--wordlist` `--timeout` `--opt-args` | findings | directory/file brute-force (C, fast) |
| `dirsearch <url>` | `--timeout` `--header` | findings | directory/file brute-force (Python, flexible) |
| `zap-scan-url <url>` | `--timeout` `--header` | findings | active scan of one exact URL, no crawling |
| `zap-scan-full <url>` | `--timeout` `--header` | findings | crawl + active scan of a whole site |
| `zap-scan-openapi <spec>` | `--timeout` `--header` | findings | active scan driven by an OpenAPI/Swagger spec |

```bash
boxcutter nuclei https://example.com --opt-args "-tags cve -severity high,critical"
boxcutter sqlmap "https://example.com/?id=1"
boxcutter dirsearch https://example.com
boxcutter zap-scan-url "https://example.com/?id=1"
boxcutter zap-scan-full https://example.com
```


### Fuzzing

| Tool | Arguments | kind | What it does |
|---|---|---|---|
| `path-fuzz <url-with-FUZZ>` | `--method` `--header` `--timeout` | findings | brute-force the `FUZZ` position with the built-in wordlist |
| `fuzz <url>` | `--method` `--data` `--header` `--status` `--timeout` `--payload` `--payload-file` `--pattern` | findings | inject params/path/body (XSS, SQLi, SSTI, LFI, RCE, XXE, NoSQL, GraphQL, error-disclosure), enumerate IDs with `{NUMBERS}`, or send your own `--payload` |

`fuzz` is signal-based, not blind. An explicit marker picks the mode: `{NUMBERS}`
(or `{NUMBERS[m-n]}`) enumerates numeric IDs for IDOR — soft-404 filtered and
deduped; `{FUZZ}` in the URL or `--data` injects payloads at that position;
unmarked, it injects every query parameter (or, if the path has ID-like segments,
each of those). Dynamic payloads (`{RANDOM}` reflection, `EXPR` evaluation) are
re-fired to confirm (fast-path ≥2/3, else ≥4/5); time-based blind injection is
reported only when response time scales monotonically with the injected delay.

**Bring your own payload** with `--payload` (repeatable) / `--payload-file` — this
skips the built-in set and sends only your payload(s) at the fuzz point (the same
points: `{FUZZ}`, query params, or ID path segments). Add `--pattern REGEX` to
report a hit only when the response matches; without it, fuzz just sends each
payload and reports what came back.

```bash
boxcutter fuzz "https://example.com/?id=1"                     # inject every query param
boxcutter fuzz "https://example.com/search?q={FUZZ}"           # inject one marked position
boxcutter fuzz "https://example.com/api/{NUMBERS}" --table     # enumerate numeric IDs (IDOR)
boxcutter fuzz "https://example.com/api/{NUMBERS[1-500]}"      # enumerate a range
boxcutter path-fuzz "https://example.com/FUZZ"
boxcutter fuzz "https://example.com/api" --method POST --data '{"q":"{FUZZ}"}'
# custom payload + pattern (only reports on match); drop --pattern to just send it
boxcutter fuzz "https://example.com/p?id=1" --payload "' OR '1'='1" --pattern "sql syntax|syntax error"
```

### Secrets / source

| Tool | Arguments | kind | What it does |
|---|---|---|---|
| `scan-secrets <url>` | — | findings | scan a response body for exposed secrets / API keys |
| `git-extract <url>` | — | findings | rebuild source from an exposed `.git` dir and scan it |

```bash
boxcutter scan-secrets https://example.com/app.js
boxcutter git-extract https://example.com/
```

### API specs

| Tool | Arguments | kind | What it does |
|---|---|---|---|
| `swagger-parser <spec>` | `--base-url` `--header` | items | parse a spec into a structured endpoint list |
| `swagger-endpoints <spec>` | `--fuzzable` `--header` | urls | spec → scannable endpoint URLs (`--fuzzable` = `{FUZZ}` variants) |
| `swagger-specs <host>` | `--header` | urls | probe common paths to find spec URLs on a host |

```bash
boxcutter swagger-parser https://api.example.com/openapi.json
boxcutter swagger-endpoints https://api.example.com/openapi.json --fuzzable
boxcutter swagger-specs api.example.com
```

### GraphQL

| Tool | Arguments | kind | What it does |
|---|---|---|---|
| `graphql-detect <host>` | `--timeout` `--header` | urls | probe common paths with `{__typename}`; list the GraphQL endpoint URL(s) |
| `graphql-audit <url>` | `--timeout` `--header` | findings | introspection, GET/CSRF, batching, verbose-error/secret leaks, schema-guided arg injection, and mutation exposure (**dry-probe only** — never executes a mutation) |

```bash
boxcutter graphql-detect api.example.com
boxcutter graphql-audit https://api.example.com/graphql
```

### Generic

| Tool | Arguments | kind | What it does |
|---|---|---|---|
| `http-request <url>` | `-D/--data` `-H/--header` | items | raw GET/POST (POST if `--data`); returns status, headers, body |

```bash
boxcutter http-request https://example.com -D "q=1"      # POST (GET without -D)
boxcutter raw nuclei -u https://example.com -t cves       # run any bundled binary natively, no JSON
```

## Workflows

A workflow chains tools and returns **one merged, source-tagged report**. Silent
by default; `--steps` shows live progress; `--arg TOOL="..."` tunes any inner
tool; `--header "K: V"` passes auth to every inner tool.

You can drop the `workflow` keyword: `boxcutter web-full example.com` is shorthand
for `boxcutter workflow web-full example.com`. A bare name resolves to a tool first
and a workflow second, so tools always win a name clash.

**Recon** — emit a list of hosts/services:

| Workflow | What it does |
|---|---|
| `recon <domain>` | subdomains (subfinder + wayback) kept if they resolve (dnsx) |
| `recon-http <domain>` | recon, then httpx — only the live HTTP(S) services |

**Scan one target:**

| Workflow | What it does |
|---|---|
| `web-full <domain\|url>` | probe live (httpx), then `web-nuclei` templates + `web-scan` full DAST per live URL |
| `web-scan <url>` | full DAST of one URL: crawl -> zap-full -> `endpoint-scan` per param URL -> swagger -> `graphql-scan` -> secrets per JS |
| `endpoint-scan <url>` | per-URL DAST bundle (the reusable unit): fuzz + nuclei -dast + sqlmap + zap-scan-url |
| `web-fuzz <url>` | like the web stage of web-full but **fuzz is the only injection tool** — crawl + swagger + graphql + secrets, no sqlmap, no ZAP active scan |
| `web-sqlmap <url>` | same as `web-fuzz` but **sqlmap is the only injection tool** — crawl + swagger + graphql + secrets, no fuzz, no ZAP active scan |
| `wayback-scan <domain>` | archive URLs -> sqlmap / fuzz / zap-scan-url per param URL, scan-secrets per JS |
| `wayback-fuzz <domain>` | wayback -> `fuzz` each param URL with **your** payload (`--arg fuzz="--payload ... --pattern ..."`), scan-secrets per JS |
| `web-crawl <url>` | Katana + ZAP crawlers, merged and deduped |
| `secrets-scan <domain>` | gather JS files (web-crawl + wayback, JS only) -> scan-secrets each |
| `swagger-scan <host\|spec>` | find spec(s) on a host (or scan a spec URL), then DAST every endpoint: fuzz + nuclei-dast + sqlmap + zap, plus zap-openapi |
| `swagger-fuzz <host\|spec>` | same discovery, **fuzz only** on every parameterised endpoint (sibling of `web-fuzz`) |
| `graphql-scan <host>` | discover GraphQL endpoint(s), then audit each (graphql-detect → graphql-audit) |

**Scan a whole environment** — start from a domain, enumerate subdomains first:

| Workflow | What it does |
|---|---|
| `env-scan <domain>` | the lot: recon -> `web-full` + `wayback-scan` per host (web-full probes liveness & covers JS secrets) |
| `env-secrets <domain>` | env-scan minus the vuln scanners: recon -> live -> crawl + secrets-scan each |
| `env-nuclei <domain>` | subfinder -> nuclei on every discovered subdomain |
| `env-takeover <domain>` | subfinder -> nuclei `-tags takeover` on every subdomain |
| `env-wayback-secrets <domain>` | subfinder -> secrets-scan (wayback + crawl -> scan-secrets) on every subdomain |
| `env-wayback <domain>` | subfinder -> wayback every subdomain -> endpoint-scan every parameterised URL |

```bash
# subdomains that resolve, as a table
boxcutter workflow recon example.com --table

# only the live HTTP(S) services
boxcutter workflow recon-http example.com --table

# full scan one site: crawl -> nuclei -> zap-full -> fuzz/sqlmap/nuclei-dast per
# param URL -> secrets per JS  (--steps prints each step)
boxcutter workflow web-full https://example.com --steps

# same scan, but report only the critical/high findings (filters the merged
# output from every inner tool; --severity also works on a single findings tool)
boxcutter workflow web-full https://example.com --severity critical,high
boxcutter nuclei https://example.com --severity critical,high

# DAST one URL, with an auth header passed to every inner tool
boxcutter workflow endpoint-scan "https://example.com/?id=1" --header "Authorization: Bearer T"

# fuzz-only DAST of one site (no sqlmap / no ZAP active scan), findings shown live
boxcutter workflow web-fuzz https://example.com --steps --show-findings

# every Swagger endpoint - point at a spec URL or a bare host
boxcutter workflow swagger-scan https://api.example.com/openapi.json
boxcutter workflow swagger-scan api.example.com

# whole environment from just a domain (subdomains enumerated first)
boxcutter workflow env-nuclei example.com --steps
boxcutter workflow env-takeover example.com
boxcutter workflow env-scan example.com --arg fuzz="--timeout 60"
```

### Authenticated scanning

Pass `--header "Name: Value"` (repeatable) to scan behind auth. On a **workflow** it
propagates to every inner tool that supports headers — fuzz, sqlmap, nuclei, dirsearch,
the swagger tools, and all four ZAP tools (which inject it into every request via the
Replacer add-on). The same flag works on each tool directly.

```bash


# --- without auth (public surface only) ---
boxcutter workflow web-full https://example.com --steps
boxcutter fuzz       "https://example.com/api/search?q=1"
boxcutter zap-scan-url "https://example.com/api/search?q=1"

# --- with auth (reaches token-gated endpoints) ---
boxcutter workflow web-full https://example.com --steps \
  --header "Authorization: Bearer TOKEN"
boxcutter fuzz         "https://example.com/api/search?q=1" --header "Authorization: Bearer TOKEN"
boxcutter zap-scan-url "https://example.com/api/search?q=1" --header "Authorization: Bearer TOKEN"

# several headers - just repeat the flag (token + API key + tenant)
boxcutter workflow endpoint-scan "https://example.com/api/x?id=1" \
  --header "Authorization: Bearer TOKEN" \
  --header "X-Api-Key: TOKEN" \
  --header "X-Tenant-Id: 42"
```

Headers are keyed by name (a repeated name keeps the last value). ZAP adds the header if
missing / replaces it if present, on spider, active-scan **and** OpenAPI-import requests.

### Scanning an OpenAPI / Swagger spec

Point a tool or workflow at the spec URL. Two engines: **ZAP** (`zap-scan-openapi` —
active scan driven from the spec) and the **swagger bundle** (`swagger-scan` — find the
spec, then fuzz + nuclei `-dast` + sqlmap + zap-scan-url per endpoint, plus zap-scan-openapi).
Add `--header` for an authenticated API.

```bash
# find / inspect the spec first (optional)
boxcutter swagger-specs api.example.com
boxcutter swagger-endpoints https://api.example.com/openapi.json --fuzzable

# --- without auth ---
boxcutter zap-scan-openapi https://api.example.com/openapi.json
boxcutter workflow swagger-scan https://api.example.com/openapi.json
boxcutter workflow swagger-scan api.example.com              # bare host: probe spec paths first

# --- with auth (header is used for the spec fetch AND every scan request) ---
boxcutter zap-scan-openapi https://api.example.com/openapi.json \
  --header "Authorization: Bearer TOKEN"
boxcutter workflow swagger-scan https://api.example.com/openapi.json \
  --header "Authorization: Bearer TOKEN"
```

Tip: `--debug` prints the `zap.sh` command, including the `-config replacer.full_list(...)`
rules, so you can confirm exactly which headers ZAP injects.

### Define your own (YAML)

Workflows are plain YAML in `boxcutter/workflows/library/`. Values flow through
named vars referenced as `${name | filter | ...}`. Every step `save:`s its output
into a var; `output:` names the var to emit. Each step states its `target:`, so
you always see what it runs on. To run steps per item in a list use `for_each` +
`do`; the current item is `${<list>.item}` (e.g. `for_each: ${live}` → `${live.item}`).

```yaml
name: endpoint-scan
input: endpoint
output: findings           # the var to emit ('findings', or a ${list} like recon)
steps:
  - tool: fuzz
    target: ${endpoint}
    args: --timeout 120
    save: findings
  - tool: sqlmap
    target: ${endpoint}
    save: findings
```

```yaml
# run several tools per parameterised URL
- for_each: ${params}
  do:
    - tool: nuclei
      target: ${params.item}
      args: --opt-args=-dast
      save: findings
    - tool: sqlmap
      target: ${params.item}
      save: findings
```

Step keys: `tool` · `target` (what to run on: `${url}`, `${params.item}`, ...) ·
`for_each` + `do` (run steps per item; current item is `${<list>.item}`) · `args` ·
`save` (var to collect into) · `pick` (extract a field) · `select` (filter only) ·
`alive` (keep hosts that resolve) · `workflow` (call another). Top-level
`output:` names the var to emit.

**Filters** reshape a list *inside* `${...}`, piped left-to-right with `|`.
They work anywhere a `${...}` is used — `for_each`, `select`, `target`, `output`:

| Filter | Effect |
|---|---|
| `params` | keep only URLs that have query parameters |
| `js` | keep only `.js` URLs |
| `dedup` | collapse param URLs sharing the same path + param names (ignores values) |
| `unique` | drop duplicate strings (order-preserving) |
| `hosts` | reduce each URL to its hostname (a bare domain is kept as-is) |
| `url` | ensure a scheme (prepend `https://` to a bare host) |

```yaml
# from a 'urls' var: keep parameterised URLs, collapse value-duplicates
- select: ${urls | params | dedup}
  save: params

# iterate just the JS files found in 'urls'
- for_each: ${urls | js}
  do:
    - tool: scan-secrets
      target: ${urls.item}
      save: findings
```

Worked examples — say a `urls` var holds:

```text
https://x/?id=1   https://x/?id=2   https://x/news?id=9
https://x/app.js  https://x/login   https://x/login

${urls | params}          -> ?id=1, ?id=2, news?id=9      only URLs with a query
${urls | params | dedup}  -> ?id=1, news?id=9             ?id=2 folds into ?id=1 (same path+param)
${urls | js}              -> app.js                       only .js files
${urls | unique}          -> drops the duplicate /login
${urls | hosts}           -> x                            just the hostname
```

Single values work the same way: `${target | url}` turns `example.com` into
`https://example.com`, and `${target | hosts}` turns `https://x/a?b=1` into `x`
(this is how `secrets-scan` feeds a URL to the crawler but a bare host to wayback).
Chaining is left-to-right, so `params | dedup` filters to parameterised URLs and
*then* collapses the value-duplicates.

**Load your own without rebuilding.** Point `BOXCUTTER_WORKFLOWS` at a directory
of `*.yaml` files to add (or override) workflows without touching Python:

```bash
# from source
BOXCUTTER_WORKFLOWS=./myflows python3 boxcutter.py workflow quick-look https://example.com

# in the container - mount the dir
docker run --rm -v "$PWD/myflows:/flows" -e BOXCUTTER_WORKFLOWS=/flows \
  boxcutter workflow quick-look https://example.com
```

Your files appear in `boxcutter workflow --list` next to the built-ins. A file
whose `name:` matches a built-in (e.g. `web-full`) **overrides** it; any other
name is **added**. They use the exact same tools, filters, and `${...}` syntax
documented above — nothing else to learn.

## AI agent (bob)

`boxcutter bob <target>` is an autonomous, LLM-driven bug-hunter built on the same tools. Instead of a
fixed workflow, a team of specialist agents **share one engagement context**, harvest credentials as they
go, chase chains across the app, and write a professional report. It is **boxcutter-only** (every action
is a boxcutter sub-command, run in-process), **provider-agnostic**, and confirm-first. It needs an LLM API
key; it streams agent progress to stderr and prints the report to stdout.

> bob is deliberately low-config: it **always** hunts aggressively on the authorized target and
> **auto-selects** which agents to run from what it discovers — there is no roster or mode to set.

### Run bob

```bash
# Anthropic (key from env)
docker run --rm -e ANTHROPIC_API_KEY boxcutter bob https://example.com

# OpenAI
docker run --rm -e OPENAI_API_KEY boxcutter bob https://example.com --provider openai --model gpt-4o

# LiteLLM gateway — pass key + endpoint as flags, so one prebuilt image hits any provider, no rebuild
docker run --rm boxcutter bob https://example.com \
  --provider litellm --api-key sk-... --base-url http://litellm:4000 --model claude-sonnet-4-6

# authenticated — give two identities so it can test BOLA/BFLA
boxcutter bob https://example.com \
  --header "Authorization: Bearer A" --header-b "Authorization: Bearer B"

# self-managed auth — give creds and bob logs in, then refreshes access/refresh tokens itself
boxcutter bob https://example.com --creds alice:pw1 --login-url https://example.com/api/login --creds-b bob:pw2

# point it at exactly what you mean — bob detects the entry shape and scopes to it
boxcutter bob example.com                              # domain   — full recon incl subdomains
boxcutter bob https://example.com/orders/5            # endpoint — just this endpoint
boxcutter bob https://api.example.com/openapi.json    # spec     — drive the documented API

# watch every step (one-line result per tool call); or dump each agent's full prompt and exit
boxcutter bob https://example.com --steps
boxcutter bob https://example.com --show-prompts
```

| Flag | Default | What |
|---|---|---|
| `--provider` | `anthropic` | `anthropic` · `openai` · `litellm` |
| `--model` | per-provider | model id (e.g. `claude-sonnet-4-6`, `gpt-4o`, or the LiteLLM route) |
| `--api-key` | provider env var | LLM key — overrides the env var |
| `--base-url` | provider default / `*_BASE_URL` env | LLM endpoint — overrides; point it at your LiteLLM gateway or a proxy |
| `--header "K: V"` | — | auth header for identity A, propagated to every agent (repeatable) |
| `--header-b "K: V"` | — | a 2nd identity for BOLA/BFLA (repeatable) |
| `--creds user:pass` | — | credentials for identity A; bob logs in and self-manages access/refresh tokens |
| `--creds-b user:pass` | — | credentials for a 2nd identity B |
| `--login-url URL` | discovered | login endpoint for `--creds` (else the auth agent tries to find it) |
| `--steps` | off | print a one-line result summary after every tool call |
| `--show-prompts` | off | print every agent's full system prompt and exit |

Scope is enforced from the target: an active call is refused if it leaves the target's domain (set
`BOB_SCOPE=host1,host2` to widen). bob is **always aggressive** (it may use PUT/PATCH/DELETE) and bounded by a
global tool-call budget — only run it against authorized targets.

### Entry modes & scope

bob reads the target and works with **exactly what you point at** — and fences itself to it:

| You give it | Mode | What bob does |
|---|---|---|
| `example.com` | **domain** | full recon incl. subdomains (`subfinder`); scope = the apex + its subdomains |
| `https://example.com` | **url** | stays on **this host only**, no subdomain enumeration |
| `https://example.com/orders/5` | **endpoint** | focuses on that single endpoint, minimal crawl |
| `https://api.example.com/openapi.json` (or `swagger`/`api-docs`/`.yaml`) | **spec** | drives the documented API from the spec |

### Models & providers

The provider, key, and endpoint each default to the environment but can be overridden by a flag — so a
**single prebuilt image** can target any model without rebuilding (set `--api-key` / `--base-url`, or the
env vars below).

| `--provider` | key (env) | base URL (env) | default model |
|---|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` | `ANTHROPIC_BASE_URL` | `claude-sonnet-4-6` |
| `openai` | `OPENAI_API_KEY` | `OPENAI_BASE_URL` | `gpt-4o` |
| `litellm` | `LITELLM_API_KEY` | `LITELLM_BASE_URL` (default `http://localhost:4000`) | set with `--model` |

`litellm` speaks the OpenAI wire format, so a LiteLLM gateway fronts any model (Claude, GPT, local) behind
one endpoint. No provider SDKs are used — bob talks to each API over plain HTTP (`requests` only).

### Orchestration

A **coordinator** drives the run adaptively — it is *not* a fixed pipeline. Each agent declares a trigger;
the coordinator runs it only when the shared context satisfies that trigger, and re-runs the exploit agents
when a credential is harvested mid-run. Every agent reads and writes one shared context, so a fact found by
one agent (a JWT, an endpoint, the app's purpose) immediately steers the next.

```text
  boxcutter bob https://target        LLM via --provider / --model / --api-key / --base-url
        │
        ▼
  ┌──────────────────────────────────────────────────────────────────────────┐
  │ COORDINATOR  —  adaptive, not a fixed pipeline                            │
  │   - runs an agent only when its trigger fires  (no API surface -> skip    │
  │     api;  no JS -> skip js-analyzer;  no findings -> skip validator)      │
  │   - re-sweeps the exploit agents when a credential is harvested mid-run   │
  └──────────────────────────────────────────────────────────────────────────┘
        │   every agent reads <-> writes the shared CONTEXT each step
        ▼
  ┌──────────────────────────────────────────────────────────────────────────┐
  │ SHARED CONTEXT (the bus)                                                  │
  │   base_url · app_profile (purpose / roles / objects / sensitive_actions)  │
  │   surface (urls / params / js / api / endpoints / tier1)                  │
  │   IDENTITIES (incl. HARVESTED jwt / cookie) · secrets · findings          │
  └──────────────────────────────────────────────────────────────────────────┘
        ▲
        │  agents (preferred order; the coordinator gates each by its trigger)
        │
   recon / map   planner · auth · discovery · browser · js-analyzer · recon-ranker · fingerprint · profile
   surface       api · graphql · exposure · config-auditor · visual
   exploit       fuzzer · access · business-logic · lateral ──┐  new credential?
                 ◄─────────────── re-sweep ──────────────────┘
   analysis      validator ─► correlator ─► reporter ─► professional report
```

A chain bob follows on its own: **`api`** reads the OpenAPI spec → calls a `/JWTTest`-style endpoint →
**harvests the JWT** into `IDENTITIES` → **`fuzzer` / `access` / `business-logic`** reuse it on the documented
endpoints → BOLA + SQLi → **`correlator`** reports it as one high-severity chain → **`reporter`** writes it
up (HackerOne-style: weakness · affected · steps to reproduce · evidence · impact · remediation).

The agents, by layer:

| Layer | Agents | Role |
|---|---|---|
| recon / map | `planner` `auth` `discovery` `browser` `js-analyzer` `recon-ranker` `fingerprint` `profile` | strategy, sessions, surface, **JS/SPA render**, JS mining, P1/P2/Kill ranking, stack + known-leak probes, and *what the app IS* |
| surface | `api` `graphql` `exposure` `config-auditor` `visual` | documented APIs, GraphQL, nuclei/.git/secrets, misconfig, open admin UIs |
| exploit | `fuzzer` `access` `business-logic` `lateral` | injection, BOLA/BFLA, rule/workflow abuse, deep-dive pivoting |
| analysis | `validator` `correlator` `reporter` | disprove false positives, build chains, write the report |

Each agent's prompt is assembled from four layers — shared **doctrine** + its **role objective** + a **tool
reference** (only its tools) + a **judgment rubric** (only its vuln classes); inspect any of them with
`boxcutter bob <target> --show-prompts`.

### Self-managed auth & browser

Give bob credentials (`--creds user:pass [--login-url …]`) and it **logs in itself**, parses the access +
refresh tokens (JSON or cookie), attaches them to every in-scope request, and **auto-refreshes / re-logs-in on
a 401** — like a real tester. For JS/SPA apps and OAuth/CSRF logins it drives a real headless browser via three
**full-image** tools (require Playwright; auto-skipped otherwise): `browser-crawl` (render + capture the real
XHR/route surface), `browser-login` (perform the actual login flow), and `browser-actions` (script clicks/typing:
`--action "fill:#user=admin" --action "click:text=Log in"`, or `--actions-file`).

### Trust the report

Findings are **evidence-bound**: a finding is only `confirmed` if its evidence actually appears in a captured
response (the validator re-tests, and the check is code-gated — the model can't confirm a bug that isn't there);
otherwise it's demoted, never silently dropped. After the report, bob prints a **machine-generated `VERIFIED RUN
FACTS`** block (tool-call counts, surface, findings by status, skipped agents, and a `LOW COVERAGE` flag for
SPA/blocked/empty targets) that the model cannot fake. Honest ceiling: bob is a **self-driving, verified-lead
generator** — not an oracle. It does **not** cover OOB/blind, non-HTTP, WAF-evasion, or CSRF-as-a-vuln.

### Test checklist (needs a real key + an authorized target)

```bash
boxcutter bob https://YOUR-AUTHORIZED-TARGET --show-prompts        # 1. prompts assemble, no key needed
ANTHROPIC_API_KEY=…  boxcutter bob https://YOUR-AUTHORIZED-TARGET --steps   # 2. watch the adaptive run
#   verify: agents skip when irrelevant, the VERIFIED RUN FACTS block prints, findings carry a status
boxcutter bob https://YOUR-TARGET/openapi.json --steps            # 3. spec mode drives the API
boxcutter bob https://YOUR-TARGET --creds user:pass --login-url … # 4. logs in + self-refreshes (full image for SPA login)
```

## Output & dependencies

Every command prints one JSON envelope on stdout (quiet by default):

```json
{ "success": true, "kind": "findings", "data": [], "error": null }
```

`data` is always a list and `kind` says what's in it, so consumers know the
shape up front:

| `kind` | `data` items | tools |
|---|---|---|
| `findings` | `{severity, title, info, url}` | nuclei, sqlmap, fuzz, scan-secrets, dirb, dirsearch, zap-scan-*, ... |
| `urls` | strings | subfinder, wayback, katana-crawl, zap-crawl, swagger-endpoints, ... |
| `items` | objects (always a `url`; `status` for HTTP code) | httpx, js-endpoints, swagger-parser, ... |

`error` is `null` on success. A tool exits 0 whenever it ran (even with zero
findings) and non-zero only on bad input, so gate on `success`/`data`, not the
exit code.

Dependencies: tools need only **Python 3 + `requests`**. Workflows additionally
need **PyYAML** to load the YAML library (bundled in the image; `pip install pyyaml`
for the pure-Python use). `naabu` ships in the image (`boxcutter raw naabu ...`).
Authorized testing only: systems you own or are permitted to assess.

## Example run

A full DAST pass over a deliberately vulnerable target, filtered to the
high/critical findings and printed as a table:

```text
docker run ghcr.io/zzzteph/boxcutter:latest workflow web-full boxcutter.appsec.study --steps --table --severity high,critical


source         severity  title                                     info                                                                    url
-------------  --------  ----------------------------------------  ----------------------------------------------------------------------  ----------------------------------------------------------------------
nuclei         high      springboot-heapdump                       [springboot-heapdump] [http] [critical] https://boxcutter.appsec.st...  https://boxcutter.appsec.study/actuator/heapdump
zap-scan-full  high      Cross Site Scripting (Reflected)          Cross Site Scripting (Reflected) via product_id <p>Cross-site Scrip...  http://boxcutter.appsec.study/reviews?product_id=%22%3E%3CscrIpt%3E...
zap-scan-full  high      SQL Injection - SQLite                    SQL Injection - SQLite via id <p>SQL injection may be possible.</p>     http://boxcutter.appsec.study/product?id=%3B
zap-scan-full  high      SQL Injection - SQLite (Time Based)       SQL Injection - SQLite (Time Based) via id <p>SQL injection may be ...  http://boxcutter.appsec.study/product?id=4
zap-scan-full  high      Cross Site Scripting (Reflected)          Cross Site Scripting (Reflected) via product_id <p>Cross-site Scrip...  https://boxcutter.appsec.study/reviews?product_id=%22%3E%3CscrIpt%3...
zap-scan-full  high      SQL Injection - SQLite                    SQL Injection - SQLite via id <p>SQL injection may be possible.</p>     https://boxcutter.appsec.study/product?id=%3B
zap-scan-full  high      SQL Injection - SQLite (Time Based)       SQL Injection - SQLite (Time Based) via category <p>SQL injection m...  https://boxcutter.appsec.study/?category=stationery
fuzz           high      [GET] [sqli] in 'id' (3 payloads)         Class:    sqli Param:    id Signal:   time_scaling Status:   200 UR...  http://boxcutter.appsec.study/product?id=1+AND+SLEEP%285%29
fuzz           high      [GET] [xss] in 'id' (2 payloads)          Class:    xss Param:    id Signal:   pattern_match Status:   200 UR...  http://boxcutter.appsec.study/product?id=%22%3E%3Cimg+src%3Dx+onerr...
sqlmap         high      SQL Injection in parameter 'id (GET)'     Parameter: id (GET)  Type: boolean-based blind   Title:   AND boole...  http://boxcutter.appsec.study/product?id=3
fuzz           high      [GET] [xss] in 'q' (5 payloads)           Class:    xss Param:    q Signal:   pattern_match Status:   200 URL...  https://boxcutter.appsec.study/search?q=%3Cscript%3Ealert%28713299%...
fuzz           high      [GET] [sqli] in 'id' (3 payloads)         Class:    sqli Param:    id Signal:   time_scaling Status:   200 UR...  https://boxcutter.appsec.study/product?id=1+AND+SLEEP%285%29
fuzz           high      [GET] [xss] in 'id' (2 payloads)          Class:    xss Param:    id Signal:   pattern_match Status:   200 UR...  https://boxcutter.appsec.study/product?id=%22%3E%3Cimg+src%3Dx+oner...
sqlmap         high      SQL Injection in parameter 'id (GET)'     Parameter: id (GET)  Type: boolean-based blind   Title:   AND boole...  https://boxcutter.appsec.study/product?id=1
fuzz           high      [GET] [xss] in 'category' (5 payloads)    Class:    xss Param:    category Signal:   pattern_match Status:   ...  https://boxcutter.appsec.study/?category=%3Cscript%3Ealert%28694985...
fuzz           high      [GET] [xss] in 'product_id' (5 payloads)  Class:    xss Param:    product_id Signal:   pattern_match Status: ...  https://boxcutter.appsec.study/reviews?product_id=%3Cscript%3Ealert...
fuzz           high      [GET] [xss] in 'q' (5 payloads)           Class:    xss Param:    q Signal:   pattern_match Status:   200 URL...  http://boxcutter.appsec.study/search?q=%3Cscript%3Ealert%28698585%2...
fuzz           high      [GET] [xss] in 'category' (5 payloads)    Class:    xss Param:    category Signal:   pattern_match Status:   ...  http://boxcutter.appsec.study/?category=%3Cscript%3Ealert%28277962%...
fuzz           high      [GET] [xss] in 'product_id' (5 payloads)  Class:    xss Param:    product_id Signal:   pattern_match Status: ...  http://boxcutter.appsec.study/reviews?product_id=%3Cscript%3Ealert%...
fuzz           high      [GET] [sqli] in 'id' (1 payload)          Class:    sqli Param:    id Signal:   time_scaling Status:   500 UR...  https://boxcutter.appsec.study/api/internal/debug-report?id=1%22+AN...
fuzz           high      [GET] [xss] in 'id' (4 payloads)          Class:    xss Param:    id Signal:   pattern_match Status:   500 UR...  https://boxcutter.appsec.study/api/internal/debug-report?id=%3Cscri...
fuzz           high      [GET] [xss] in 'email' (1 payload)        Class:    xss Param:    email Signal:   pattern_match Status:   500...  https://boxcutter.appsec.study/api/internal/user-lookup?email=%27%3...
sqlmap         high      SQL Injection in parameter 'email (GET)'  Parameter: email (GET)  Type: UNION query   Title:   Generic UNION ...  https://boxcutter.appsec.study/api/internal/user-lookup?email=
fuzz           high      [GET] [xss] in 'id' (4 payloads)          Class:    xss Param:    id Signal:   pattern_match Status:   500 UR...  http://boxcutter.appsec.study/api/internal/debug-report?id=%3Cscrip...
fuzz           high      [GET] [xss] in 'email' (1 payload)        Class:    xss Param:    email Signal:   pattern_match Status:   500...  http://boxcutter.appsec.study/api/internal/user-lookup?email=%27%3E...
sqlmap         high      SQL Injection in parameter 'email (GET)'  Parameter: email (GET)  Type: UNION query   Title:   Generic UNION ...  http://boxcutter.appsec.study/api/internal/user-lookup?email=
fuzz           high      [GET] [xss] in 'user' (4 payloads)        Class:    xss Param:    user Signal:   pattern_match Status:   200 ...  https://boxcutter.appsec.study/api/directory?user=%3Cscript%3Ealert...
fuzz           high      [GET] [lfi] in 'name' (2 payloads)        Class:    lfi Param:    name Signal:   pattern_match Status:   200 ...  https://boxcutter.appsec.study/api/files?name=%2Fetc%2Fpasswd
fuzz           high      [GET] [xss] in 'name' (5 payloads)        Class:    xss Param:    name Signal:   pattern_match Status:   404 ...  https://boxcutter.appsec.study/api/files?name=%3Cscript%3Ealert%281...
fuzz           high      [GET] [lfi] in 'lang' (6 payloads)        Class:    lfi Param:    lang Signal:   pattern_match Status:   200 ...  https://boxcutter.appsec.study/api/i18n?lang=%2Fetc%2Fpasswd
fuzz           high      [GET] [xss] in 'lang' (4 payloads)        Class:    xss Param:    lang Signal:   pattern_match Status:   404 ...  https://boxcutter.appsec.study/api/i18n?lang=%3Cscript%3Ealert%2857...
fuzz           high      [GET] [ssti] in 'message' (3 payloads)    Class:    ssti Param:    message Signal:   pattern_match Status:   ...  https://boxcutter.appsec.study/api/messages/preview?message=%7B%7B6...
fuzz           high      [GET] [xss] in 'message' (4 payloads)     Class:    xss Param:    message Signal:   pattern_match Status:   2...  https://boxcutter.appsec.study/api/messages/preview?message=%3Cscri...
fuzz           high      [GET] [xss] in 'q' (1 payload)            Class:    xss Param:    q Signal:   pattern_match Status:   500 URL...  https://boxcutter.appsec.study/api/products?q=%27%3E%3Csvg+onload%3...
sqlmap         high      SQL Injection in parameter 'q (GET)'      Parameter: q (GET)  Type: UNION query   Title:   Generic UNION quer...  https://boxcutter.appsec.study/api/products?q=1
fuzz           high      [GET] [xss] in 'code' (3 payloads)        Class:    xss Param:    code Signal:   pattern_match Status:   200 ...  https://boxcutter.appsec.study/api/promos?code=%3Cscript%3Ealert%28...
fuzz           high      [GET] [xss] in 'weight' (4 payloads)      Class:    xss Param:    weight Signal:   pattern_match Status:   50...  https://boxcutter.appsec.study/api/shipping/quote?weight=%3Cscript%...
fuzz           high      [GET] [xss] in 'name' (4 payloads)        Class:    xss Param:    name Signal:   pattern_match Status:   200 ...  https://boxcutter.appsec.study/api/staff?name=%3Cscript%3Ealert%282...
fuzz           high      [GET] [rce] in 'host' (10 payloads)       Class:    rce Param:    host Signal:   pattern_match Status:   200 ...  https://boxcutter.appsec.study/api/tools/dns?host=%3Bid
fuzz           high      [GET] [xss] in 'host' (4 payloads)        Class:    xss Param:    host Signal:   pattern_match Status:   200 ...  https://boxcutter.appsec.study/api/tools/dns?host=%3Cscript%3Ealert...
```

## Credits

boxcutter is a thin wrapper — the scanning is done by these projects, all credit
to their authors:

- [ProjectDiscovery](https://github.com/projectdiscovery) — `subfinder`, `dnsx`, `naabu`, `katana`, `nuclei`, `httpx`
- [OWASP ZAP](https://www.zaproxy.org/) — crawling and active scanning (`zap-crawl`, `zap-scan-*`)
- [sqlmap](https://sqlmap.org/) — SQL injection (`sqlmap`)
- [dirb](https://dirb.sourceforge.net/) + [dirsearch](https://github.com/maurosoria/dirsearch) — content discovery

The original parts are just the CLI, the JSON envelope, and the YAML workflow
layer; everything else is these tools, wrapped to speak one format.

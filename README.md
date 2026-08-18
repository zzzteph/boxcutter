<p align="center">
  <img src="logo.png" alt="boxcutter" width="200">
</p>

# boxcutter

A pentesting toolkit in one container.

One CLI over ProjectDiscovery, OWASP ZAP, sqlmap, dirb, dirsearch, and some Python
recon/fuzz tools. Point it at a target, get one JSON result.

> ⚠️ Active, intrusive scanning. Only run it against systems you're authorized to test.

## Install

```bash
docker pull ghcr.io/zzzteph/boxcutter:latest
docker tag  ghcr.io/zzzteph/boxcutter:latest boxcutter

docker run --rm boxcutter --list             # tools
docker run --rm boxcutter workflow --list    # workflows
```

Below, `boxcutter <args>` = `docker run --rm boxcutter <args>`. Add `--table` for readable
output, `--steps` to watch a workflow run, `--header "K: V"` for auth (repeatable).

## Scan

```bash
# whole scan of one site
boxcutter web-full https://example.com --table
boxcutter web-full https://example.com --severity critical,high     # worst only
boxcutter web-full https://example.com --header "Authorization: Bearer T"   # behind auth

# one URL / one param
boxcutter endpoint-scan "https://shop.example.com/product?id=1"
boxcutter fuzz "https://example.com/search?q=1"                     # inject every param
boxcutter fuzz "https://example.com/api/orders/{NUMBERS}"           # enumerate IDs (IDOR)
boxcutter sqlmap "https://example.com/item?id=1"

# an API
boxcutter swagger-scan https://api.example.com/openapi.json
boxcutter swagger-scan api.example.com                              # find the spec first
boxcutter graphql-audit https://api.example.com/graphql

# map the app in a headless browser (SPA-aware: clicks links, submits forms, captures every request)
boxcutter harvest https://app.example.com                          # dedupe into an endpoint corpus
boxcutter harvest https://app.example.com --har traffic.har        # + a Burp/ZAP-importable HAR
boxcutter harvest https://app.example.com --header "Cookie: session=..."    # authenticated crawl

# start from a domain
boxcutter recon example.com                                        # subdomains that resolve
boxcutter env-scan example.com --steps                             # scan the whole environment
boxcutter env-takeover example.com                                 # subdomain takeover sweep

# secrets & source
boxcutter secrets-scan example.com
boxcutter git-extract https://example.com/                         # rebuild an exposed .git

# custom payload, report only on match
boxcutter fuzz "https://example.com/p?id=1" --payload "' OR '1'='1" --pattern "sql syntax|error"

# run any bundled binary natively
boxcutter raw nuclei -u https://example.com -t cves
```

**Tools:** `subfinder` `dnsx` `httpx` `screenshot` `wayback` · `katana-crawl` `zap-crawl`
`js-endpoints` `harvest` · `nuclei` `sqlmap` `dirb` `dirsearch` `zap-scan-*` · `fuzz`
`path-fuzz` · `scan-secrets` `git-extract` · `swagger-*` `graphql-*` · `http-request`.
**Workflows:** `web-full` `web-scan` `spa-scan` `endpoint-scan` `web-fuzz` `web-sqlmap` `swagger-scan`
`graphql-scan` `secrets-scan` `recon` `env-scan` `env-nuclei` `env-takeover`.

`boxcutter <cmd> --help` for options. Custom workflows: drop YAML in
`boxcutter/workflows/library/` or point `BOXCUTTER_WORKFLOWS` at a dir.

## Browser crawl (SPA)

`harvest` drives the target in a real headless browser (Chromium over CDP): it clicks links,
submits forms, and follows routes across the app, capturing every request the page makes (GET
and POST, XHR/fetch and full navigations), including the cross-origin `api.*` backend a plain
spider never sees. It dedupes into an endpoint corpus (path ids templated to `{id}`), records
a parameter catalog, and can write a Burp/ZAP-importable HAR. Every captured request carries a
copy-paste curl and a raw request.

```bash
boxcutter harvest https://app.example.com
boxcutter harvest https://app.example.com --capture-host "*.example.com"   # keep the org, drop trackers/CDNs
boxcutter harvest https://app.example.com --header "Cookie: session=..." --har traffic.har   # authed + HAR
boxcutter harvest https://app.example.com | jq -r '.data[].curl'           # every request as a curl
```

`harvest` also feeds the shared `web-crawl` step, so `web-full` and `web-scan` pick up a SPA's
API surface. The `spa-scan` workflow chains it into the scanners: harvest the app, then
DAST each parameterised URL (fuzz + nuclei-dast + sqlmap + zap-scan-url), plus GraphQL audit
and secrets on each JS file.

```bash
boxcutter workflow spa-scan https://app.example.com --header "Cookie: session=..."
```

Under docker, mount a dir for the HAR: `docker run --rm -v "$PWD:/out" boxcutter harvest
https://app.example.com --har /out/traffic.har`. Needs the full image (bundles chromium).

## AI agents

LLM-driven agents that drive the same tools on their own. Each needs a provider and API key
(`--provider` / `--api-key`, or `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`) and makes many calls.
List them with `boxcutter ai --list`; run one with `boxcutter ai <agent> <target>` (or bare
`boxcutter <agent>` when no tool shares the name). Under docker, pass the key through:
`docker run --rm -e ANTHROPIC_API_KEY boxcutter irvin example.com`.

- `irvin`: the conductor. Runs travis, then bob, then caleb over a whole domain, verifies and
  consolidates the findings, and writes a CEO executive summary plus a technical report. It
  streams every agent's reasoning live and can dump it per agent.
- `bob`: surface scanner, highlights exposed attack surface.
- `caleb`: multi-phase, multi-identity orchestrator (authenticated deep scan, reauth, two-account BFLA).
- `travis`: recon triage, rates how interesting a host is before a deeper scan.
- `crawlio`: crawler that builds a code-verified endpoint list.
- `prawlio`: authenticated crawl (logs in, then crawls under that session).
- `logio`: auth-only agent that logs in with supplied creds.
- `juicy`: JS analyst, pulls hidden URLs, DOM XSS, and secrets from a JS file or page.

```bash
# full engagement from a domain: recon, rank hosts, bob, then caleb, into a verified report
boxcutter irvin example.com

# scan an explicit list of hosts and skip discovery (or --hosts-file targets.txt, one per line)
boxcutter irvin --hosts app.example.com,api.example.com --report report.md

# quick pass (bob only, skip caleb's deep pass) and save the CEO + findings report
boxcutter irvin example.com --quick --report report.md

# authenticated deep scan with two identities for BOLA/BFLA, top 3 ranked hosts only
boxcutter irvin app.example.com --creds user:pass --creds-b user2:pass2 --max-hosts 3

# dump every agent's reasoning (native thinking + narration) and all artifacts to folders
boxcutter irvin example.com --reasoning-dir reasoning/ --out-dir run/

# turn native thinking off for a cheaper run, or widen which host tiers get scanned
boxcutter irvin example.com --reasoning 0 --tiers critical,high,medium
```

## Output

One JSON envelope on stdout: `{ "success": true, "kind": "findings", "data": [...], "error": null }`.
`kind` is `findings` | `urls` | `items`. Gate on `success`/`data`, not the exit code.
Tools need Python 3 and `requests`; workflows need PyYAML. Both are bundled in the image.

## Credits

Scanning is done by these projects. Credit to their authors:

- [ProjectDiscovery](https://github.com/projectdiscovery): `subfinder`, `dnsx`, `naabu`, `katana`, `nuclei`, `httpx`
- [OWASP ZAP](https://www.zaproxy.org/): crawling and active scanning
- [sqlmap](https://sqlmap.org/): SQL injection
- [dirb](https://dirb.sourceforge.net/) + [dirsearch](https://github.com/maurosoria/dirsearch): content discovery

boxcutter adds the CLI, the JSON envelope, and the YAML workflows.

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
`js-endpoints` · `nuclei` `sqlmap` `dirb` `dirsearch` `zap-scan-*` · `fuzz` `path-fuzz` ·
`scan-secrets` `git-extract` · `swagger-*` `graphql-*` · `http-request`.
**Workflows:** `web-full` `web-scan` `endpoint-scan` `web-fuzz` `web-sqlmap` `swagger-scan`
`graphql-scan` `secrets-scan` `recon` `env-scan` `env-nuclei` `env-takeover`.

`boxcutter <cmd> --help` for options. Custom workflows: drop YAML in
`boxcutter/workflows/library/` or point `BOXCUTTER_WORKFLOWS` at a dir.

## AI agents

LLM-driven agents that drive the same tools on their own. Each needs a provider and API key
(`--provider` / `--api-key`, or `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`) and makes many calls.
List them with `boxcutter ai --list`; run one with `boxcutter ai <agent> <target>` (or bare
`boxcutter <agent>` when no tool shares the name).

- `bob`: surface scanner, highlights exposed attack surface.
- `caleb`: multi-phase, multi-identity orchestrator (authenticated deep scan, reauth, two-account BFLA).
- `travis`: recon triage, rates how interesting a host is before a deeper scan.
- `crawlio`: crawler that builds a code-verified endpoint list.
- `prawlio`: authenticated crawl (logs in, then crawls under that session).
- `logio`: auth-only agent that logs in with supplied creds.
- `juicy`: JS analyst, pulls hidden URLs, DOM XSS, and secrets from a JS file or page.

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

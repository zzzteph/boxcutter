<p align="center">
  <img src="logo.png" alt="boxcutter" width="200">
</p>

# boxcutter

**A pentesting toolkit in one container — plus IRVIN, an autonomous AI pentester.**

One CLI over ProjectDiscovery, OWASP ZAP, sqlmap, dirb, dirsearch + Python recon/fuzz
tools. Point it at a target, get one clean JSON result. Or hand it to **IRVIN** and let
the agent hack for you.

> ⚠️ Active, intrusive scanning — only against systems you're authorized to test.

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

## IRVIN — autonomous AI pentester

Give it a target; it plans, tests, **verifies its own findings**, and reports — driving the
same tools in its own loop. Needs an LLM API key.

```bash
# simplest — Anthropic key from the environment
boxcutter irvin https://example.com

# pick provider/model (anthropic | openai | litellm)
boxcutter irvin https://example.com --provider openai --model gpt-4o --api-key sk-...

# OpenAI-compatible gateway
boxcutter irvin https://example.com --provider litellm --model "openai/gpt-5.1" \
  --api-key ... --base-url https://your-gateway.example.com

# log in and hunt (it finds the login page itself; multi-step / OIDC ok)
boxcutter irvin https://example.com --creds "user@example.com:PASS"

# two identities → cross-user / BOLA testing
boxcutter irvin https://example.com \
  --creds "alice@example.com:PASS" --creds-b "bob@example.com:PASS"

# rules in plain language: scope, focus, and a header sent on every request (kept private)
boxcutter irvin https://example.com \
  --context "SPA; API on api.example.com; scope *.example.com; send X-Debug: 1 on every request; focus on checkout; /admin out of scope"

# scope a whole domain explicitly
boxcutter irvin https://example.com --scope "*.example.com"

# save the full decision trail / diagrams
boxcutter irvin https://example.com --trail run.json --graph run.dot

# run ONE agent in isolation (no council/planner) — quick sanity check
boxcutter irvin https://example.com --agent explore --agent-brief "walk the logged-in UI, map the real API"
boxcutter irvin https://example.com --agent recon
```

Specialists it runs: `recon`, `explore` (browses the live app with a real logged-in browser
+ vision, maps the true API), `dirbust`, `access-control` (IDOR/BOLA/BFLA), `web-vuln-triage`,
`sqli`, `xss`, `path-traversal`, `git-dumper`, `secrets`, `exposure`, `auth`.
`boxcutter irvin --help` for all options (API key also via `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`).

## Output

One JSON envelope on stdout: `{ "success": true, "kind": "findings", "data": [...], "error": null }`.
`kind` is `findings` | `urls` | `items`. Gate on `success`/`data`, not the exit code.
Tools need Python 3 + `requests`; workflows need PyYAML; IRVIN needs an LLM key — all bundled
in the image.

## Credits

Scanning is done by these projects — all credit to their authors:

- [ProjectDiscovery](https://github.com/projectdiscovery) — `subfinder`, `dnsx`, `naabu`, `katana`, `nuclei`, `httpx`
- [OWASP ZAP](https://www.zaproxy.org/) — crawling and active scanning
- [sqlmap](https://sqlmap.org/) — SQL injection
- [dirb](https://dirb.sourceforge.net/) + [dirsearch](https://github.com/maurosoria/dirsearch) — content discovery

boxcutter adds the CLI, JSON envelope, YAML workflows, and the IRVIN agent pipeline.

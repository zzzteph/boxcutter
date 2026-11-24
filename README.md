<p align="center">
  <img src="logo.png" alt="boxcutter" width="200">
</p>

# boxcutter

A pentesting toolkit in one container.

One CLI over ProjectDiscovery (subfinder, dnsx, httpx, katana, nuclei), sqlmap, trufflehog and a few Python
recon / fuzz / API tools, plus a web UI that runs scans across a fleet of scanners. Point it at a target, get
one JSON result — or schedule it and get told what changed.

> ⚠️ Active, intrusive scanning. Only run it against systems you're authorized to test.

## Install

```bash
docker pull ghcr.io/zzzteph/boxcutter:latest
docker tag  ghcr.io/zzzteph/boxcutter:latest boxcutter

docker run --rm boxcutter --list             # tools
docker run --rm boxcutter workflow --list    # workflows
```

Below, `boxcutter <args>` = `docker run --rm boxcutter <args>`. Add `--table` for readable output, `--steps`
to watch a workflow run, `--header "K: V"` for auth (repeatable).

## Scan from the CLI

```bash
# a website
boxcutter web-full https://example.com --table
boxcutter web-full https://example.com --severity critical,high               # worst only
boxcutter web-full https://example.com --header "Authorization: Bearer T"     # behind auth

# one URL / one parameter
boxcutter endpoint-scan "https://shop.example.com/product?id=1"
boxcutter fuzz "https://example.com/search?q=1"                    # inject every param
boxcutter fuzz "https://example.com/api/orders/{NUMBERS}"          # enumerate IDs (IDOR)
boxcutter sqlmap "https://example.com/item?id=1"

# APIs
boxcutter swagger-scan https://api.example.com/openapi.json
boxcutter graphql-scan https://api.example.com

# a JS / single-page app in a real headless browser
boxcutter harvest https://app.example.com
boxcutter spa-scan https://app.example.com --header "Cookie: session=..."

# a whole domain
boxcutter recon example.com                 # subdomains that resolve
boxcutter env-scan example.com --steps      # every subdomain, full scan
boxcutter env-takeover example.com          # subdomain takeover sweep

# secrets in JavaScript
boxcutter secrets-scan example.com

# run any bundled binary natively
boxcutter raw nuclei -u https://example.com -t cves
```

**Tools:** `subfinder` `dnsx` `dns-brute` `ping-scan` `httpx` `wayback` `wayback-domains` · `katana-crawl`
`harvest` `js-endpoints` · `nuclei` `sqlmap` `fuzz` · `scan-secrets` · `swagger-specs` `swagger-endpoints` ·
`graphql-detect` `graphql-audit`. Only the tools the bundled workflows use ship.

**Workflows:** `web-full` `web-scan` `web-nuclei` `web-fuzz` `web-sqlmap` `spa-scan` `endpoint-scan` `web-crawl`
`swagger-scan` `swagger-fuzz` `graphql-scan` `secrets-scan` `wayback-scan` `wayback-fuzz` `recon` `recon-http`
`ip-discover` `env-scan` `env-nuclei` `env-takeover` `env-secrets` `env-wayback` `env-wayback-secrets`.

`boxcutter <cmd> --help` for options. Custom workflows: drop YAML in `boxcutter/workflows/library/` or point
`BOXCUTTER_WORKFLOWS` at a dir.

## Web UI

```bash
docker run -d --name boxcutter -p 8000:8000 -v boxcutter-data:/data ghcr.io/zzzteph/boxcutter serve
```

Open `http://<host>:8000`. The browser asks for a login: **`admin` / `admin`** (HTTP basic auth, one account).
Change the password under **Settings** — the UI reminds you until you do. `ADMIN_PASSWORD` sets the first-boot
password instead. Put TLS (a reverse proxy) in front for anything beyond localhost: basic auth sends the password
with every request.

The server includes a built-in scanner that runs 2 jobs in parallel; change that live on the **Scanners** page or
add more scanners (below).

**New scan** is three steps on one page:

1. **What to scan** — paste domains, URLs, IPs or CIDRs (or upload a list). The kind is detected as you type.
2. **What to do** — scan-type cards that fit those targets: a short *Recommended* row, then groups (Websites,
   Environment, Discovery, APIs, Secrets, Web archive, Network), a search box, and single tools folded under
   *Advanced*. Each card says what it needs, what it gives and how heavy it is. For any workflow that has one,
   **Distribute across scanners** runs its distributed version (on by default when you have 2+ job slots).
3. **When** — run once now, or **repeat on a schedule** (hourly … monthly, or custom), which creates a scheduler.

A summary bar says exactly what will run before you start it.

**Schedulers** are named recurring scans: what, on what targets, how often. Each run is compared with the
previous one, so findings are *new*, *open* or *resolved*. A run never starts while the previous one is still
going. Pause, resume, run now or edit from the Schedulers page.

**Pipelines** chain scan types: step 1 runs on your targets; each next step takes the results of earlier steps,
filtered by data type — *hostnames*, *URLs*, *URLs with parameters*, *JavaScript files*, *POST/PUT requests* —
and runs on every one of them as a **separate job, shared by all scanners**. Results stream: the next step
starts as soon as the first result arrives. Example: *Find subdomains* → *httpx* → *nuclei on each live site*.
A step can read from several earlier steps (their union, de-duplicated) and can be another pipeline.

**Built-in distributed workflows**: every bundled workflow that loops over hosts or URLs also exists as a
pipeline (21 of them, e.g. `env-scan` as 23 steps), so a big scan spreads over the whole fleet instead of
running in one process. They are read-only; duplicate one to customise it.

**Notifications** (Settings): Telegram and Slack (incoming webhook) — new findings of the severities you pick,
and a summary when a scan finishes. `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` / `SLACK_WEBHOOK_URL` pre-fill
them on first boot.

There is no public REST API: the server's `/api` routes exist only for its own UI (no API keys, no OpenAPI docs,
no CORS).

## Scanners (agents)

Every scanner pulls jobs from the server and runs them. More scanners = faster scans, especially distributed
workflows and pipelines. On the server's **Scanners** page click **New enroll token**, then on any host:

```bash
docker run -d --name boxcutter-agent \
  ghcr.io/zzzteph/boxcutter agent --server https://scanner.example.com --token <ENROLL_TOKEN>
```

Change how many jobs it runs at once (`--concurrency N`, default 2) live from the Scanners page. The agent only
needs to reach the server; the server never connects back. Put TLS in front of the *server* for remote agents.

Each agent also serves a small control UI on port `7070` (HTTP basic auth, `admin` / `admin`, changeable there;
`RUNNER_UI_PASSWORD` sets the initial one) to change its server, token and concurrency. It can redirect where the
agent sends results, so publish it to loopback only and tunnel to it:

```bash
docker run -d --name boxcutter-agent -p 127.0.0.1:7070:7070 \
  ghcr.io/zzzteph/boxcutter agent --server https://scanner.example.com --token <ENROLL_TOKEN>
ssh -L 7070:127.0.0.1:7070 user@agent-host     # then open http://localhost:7070
```

From a source checkout (no Docker): `pip install -r requirements.txt`, build the UI (`cd web && npm ci && npm run
build && ln -s ../web/dist ../server/web_dist`), then `boxcutter serve`.

### Quick reference

| mode | command | port | notes |
|------|---------|------|-------|
| engine | `boxcutter <tool\|workflow> <target>` | - | one scan, JSON envelope on stdout |
| server | `boxcutter serve` | `8000` | web UI + built-in scanner; persist with `-v boxcutter-data:/data` |
| agent | `boxcutter agent --server <URL> --token <T>` | `7070` | scale-out scanner; publish `7070` to loopback only |

| env | default | purpose |
|-----|---------|---------|
| `ADMIN_PASSWORD` | `admin` | first-boot UI password (then change it in Settings) |
| `DATABASE_URL` | `sqlite:////data/boxcutter.db` | or `postgresql+psycopg://…` / `mysql+pymysql://…` |
| `ENROLL_TOKEN` | generated | token the built-in scanner (and any agent) enrolls with |
| `CONCURRENCY` | `2` | parallel jobs of a scanner (0 = idle) |
| `RUNNER_UI_PORT` | `7070` | agent control-UI port |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `SLACK_WEBHOOK_URL` | - | pre-fill notifications |

## Output

One JSON envelope on stdout: `{ "success": true, "kind": "findings", "data": [...], "error": null }`.
`kind` is `findings` | `urls` | `items`. Gate on `success`/`data`, not the exit code.

## Credits

Scanning is done by these projects. Credit to their authors:

- [ProjectDiscovery](https://github.com/projectdiscovery): `subfinder`, `dnsx`, `katana`, `nuclei`, `httpx`
- [sqlmap](https://sqlmap.org/): SQL injection
- [trufflehog](https://github.com/trufflesecurity/trufflehog): secret detection
- [nmap](https://nmap.org/): host discovery

boxcutter adds the CLI, the JSON envelope, the YAML workflows, the distributed pipeline engine and the UI.

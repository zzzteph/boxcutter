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

**Tools:** `subfinder` `dnsx` `dns-brute` `ping-scan` `httpx` `liveless` `wayback` `wayback-domains` ·
`katana-crawl` `harvest` `js-endpoints` · `nuclei` `sqlmap` `fuzz` · `scan-secrets` · `swagger-specs`
`swagger-endpoints` · `graphql-detect` `graphql-audit`. Only the tools the bundled workflows use ship.

**Templates** (YAML workflows of the engine): `web-full` `web-scan` `web-nuclei` `web-fuzz` `web-sqlmap` `spa-scan` `endpoint-scan` `web-crawl`
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
2. **What to do** — two tabs of cards that fit those targets: **Workflows** (multi-step, the work spreads over all
   scanners) and **Templates** (one job per target: a bundled scan template or a single tool). A short
   *Recommended* row comes first, then groups (Websites, Environment, Discovery, APIs, Secrets, Web archive,
   Network) and a search box. Pick a workflow and its graph is drawn right there, so you see how it will run.
   Workflows that probe live services have a **🌐 internet-reachable only** switch: the same workflow with a
   `liveless` check right after httpx (or on the targets first, for the ones that start from a URL), so only what
   answers from the public internet is scanned.
3. **When** — run once now, or **on a schedule**: a cron expression with a time zone (presets for the usual ones),
   checked live — "At 03:00 on Monday · next: Mon 30 Nov 03:00, …". That creates a scheduler. Plus a **scan
   window** (business hours): Any time, Business hours, Outside business hours, Nights, or paint any hours of the
   week on a 7 × 24 grid, in a time zone of your choice.

A summary bar says exactly what will run before you start it.

**Workflows** are graphs of steps. Every step runs one tool once per item it receives — each run a separate job
that any scanner picks up — and hands what it finds (hostnames, URLs, URLs with parameters, JavaScript files,
POST/PUT requests) to the steps wired after it, as soon as each job finishes.

- **Every box is visible.** Built-in workflows are made of single tools only — nothing hides inside a nested box —
  so parallel branches are side by side on the graph (e.g. *Whole environment scan*: 29 steps).
- **Merge** steps bring parallel steps together: one stream, duplicates dropped, no job of its own (e.g. subfinder,
  web-archive hostnames and DNS brute-force → *All discovered hostnames*). A step with several inputs merges them
  the same way.
- **Typed wires.** A step gives hostnames or URLs and takes only what it can use: hostnames never go straight into a
  URL step (httpx turns them into URLs), and hostnames from passive discovery (subfinder, dns-brute, web-archive
  hostnames) always go through **dnsx** to be verified first. The builder won't draw a wire that breaks this — while
  you drag, the steps that can take the data light up and the others say why not — and the server checks the same.
- **SQL injection is double-checked:** a fuzz step's SQL-injection hits are only leads — wired into sqlmap
  ("SQL-injection leads"), sqlmap re-tests exactly those requests and its verdict is what gets reported.
- **Follow the data:** click a wire to light up where its data goes, or a step to light up everything feeding it
  and everything it feeds (on every graph: the builder, built-in workflows, a live scan).

Build your own in the **workflow builder**: add tools (or a whole workflow — it is added as all its steps) from the
palette, drag from a step's dot onto another step to wire them, name steps, use the *Add next* suggestions. A
workflow saved with nested workflow boxes can be expanded into its steps with one click. Every bundled template
that loops over hosts or URLs ships as a built-in workflow (21 of them, 16 also as an internet-reachable-only
twin) — open one to see its graph, duplicate it to change it.

**A scan's page** shows its workflow **live**: every step with its state, jobs, what it found and its findings,
wires animated while data flows. Click a step for its own log and to filter findings / discovered assets / jobs
to just that step.

**Schedulers** are named recurring scans: what, on what targets, and a cron schedule. Every run (scheduled, "Run
now" or "Run again") starts over from the first steps on your targets and flows through the whole workflow again.
When it finishes, the findings are brought up to date: ones found for the first time are **new**, ones found again
stay **open**, and ones that are **no longer found are removed** — the list always shows what is there now. A
finding is only removed when its step actually re-checked that target and came back clean; if the job failed or the
target wasn't reached this time, the finding stays, marked **not re-checked**. Every removal is listed in Activity
and in the scan-done Slack/Telegram message, so you can see what got fixed. Runs never stack: if one is still going
at the next tick, that tick is skipped (and logged).

**Scan windows** (business hours) limit *when a scan's jobs run*, per scan or scheduler: outside the window no new
job starts (ones already running finish) and the scan page says when it opens again. A scheduled run whose cron
tick falls outside the window starts and waits for it. Change it any time from the scan page or the scheduler —
it applies at once, also to a run in progress.

**Notifications** (Settings): Telegram and Slack (incoming webhook) — new findings of the severities you pick,
and a summary when a scan finishes. `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` / `SLACK_WEBHOOK_URL` pre-fill
them on first boot.

There is no public REST API: the server's `/api` routes exist only for its own UI (no API keys, no OpenAPI docs,
no CORS).

## Scanners (agents)

Every scanner pulls jobs from the server and runs them. More scanners = faster scans, especially
workflows. On the server's **Scanners** page click **New enroll token**, then on any host:

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
- [liveless](https://liveless.shrewdeye.app/): external reachability probe (the internet-reachable-only workflows
  send the URLs they check to it)

boxcutter adds the CLI, the JSON envelope, the YAML templates, the distributed workflow engine and the UI.

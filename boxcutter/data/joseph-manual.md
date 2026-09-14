# joseph — operator manual

`boxcutter ai joseph` is a **human-operator** security agent. One LLM brain both **decides and acts**: it opens
a real browser and stays logged in, watches the traffic as it clicks, drives the full boxcutter tool registry,
**writes and runs its own scripts** in the container, and works a **mission goal** — not a checklist. It thinks
out loud the whole way, and several read-only analysts work alongside it in parallel.

For the design rationale, see `docs/joseph-design.md` in the repo. This file is how to **run** it, and ships
on-disk in the image next to the wordlists (`/opt/boxcutter/boxcutter/data/joseph-manual.md`).

---

## 1. Requirements

- The **full** boxcutter image (chromium + ZAP + Java + Node — the browser, the traffic sink, and crack-js).
- An **LLM**: a provider + model + key, or a gateway. joseph passes `--provider/--model/--api-key/--llm-proxy-url`
  straight through to the provider layer.
- Network egress from the container to **both** the target **and** the LLM endpoint.

joseph degrades gracefully where a piece is missing (e.g. ZAP down → cdp in-process capture), but the browser
and an LLM are hard requirements.

---

## 2. Quick start

```sh
podman run --rm \
  -v "$PWD/joseph_run:/data/joseph_run" \
  boxcutter ai joseph https://app.example.com \
    --provider litellm --model bedrock/eu.anthropic.claude-opus-4-8 \
    --llm-proxy-url https://your-gateway.example \
    --api-key sk-... \
    --context "Explore deeply and find all vulnerabilities; CTF — goal = get access to the server" \
    --out-dir /data/joseph_run \
    --debug --table
```

- `--out-dir` is **optional** (defaults to `joseph_<host>_<ts>`). But the workspace is written **inside** the
  container; mount a volume and point `--out-dir` into it to keep the artifacts (see §7 and §16).
- The findings + full report always come back on **stdout** regardless of the mount.
- `--debug` shows every tool call and browser step. The reasoning stream is on by default (§6).

---

## 3. Input: the mission brief (`--context`)

joseph is **goal-directed**. Its primary input is the `--context` brief — the **goal**, the **endpoints** in
play, and how to **authenticate** — not a bare URL. The positional `target` is optional: if omitted, joseph
derives the app root and scope from the URLs named in `--context`.

Scope = the target's registrable domain **plus** every host named in the brief (a goal often spans a UI host +
an `api.` backend). Unrelated third-party hosts stay out of scope.

```sh
--context "Goal: reach the admin dashboard and read another tenant's orders.
Endpoints: https://app.x.com , https://api.x.com/v2 .
Auth: Cookie: session=abc123  (or: creds alice:alice at https://app.x.com/login)"
```

Auth material in the brief (a `Cookie:`/`Authorization:` header, or credentials) is parsed out and applied.

---

## 4. Authentication

- **Header/cookie auth:** put it in `--context` or pass `-H "Authorization: Bearer …"`. It is threaded into
  every tool call and the browser.
- **Form login:** `--creds user:pass` (and optional `--creds-b user:pass` for a second identity, for
  two-account BOLA/BFLA). A dedicated **auth agent** drives the real browser to log in **before** the main run,
  confirms the session is authenticated, then publishes identity A's cookie/bearer as the tools' auth headers —
  so everything downstream (tools, analysts, scripts) runs authenticated. `--login-url` overrides the login
  page (default: the target).

---

## 5. What it does each run (roles)

- **Driver** — the operator loop. The **sole** writer to the live browser session. Opens the app, clicks,
  reads traffic, runs tools, writes scripts, mutates in-scope, leases analyst leads, and drives toward the goal.
- **Analysts** — parallel **read-only** consumers, one per lane. They read the shared workspace bus and post
  **leads** for the driver to test live. They may run every non-destructive tool in their lane (incl.
  fuzz/sqlmap/nuclei/bola-walk) but never touch the live session or mutate. Lanes: `recon-surface`, `js-xss`,
  `auth-idor`, `sqli`, `injection`, `secrets`, `api-graphql`, `business-logic`, `ssrf-redirect`.

`--analysts N` runs the first N lanes (default: all 9). `--analysts 0` = pure single-operator. `--analyst-steps`
caps each analyst's budget (default 40).

---

## 6. Watching it think

The **reasoning stream** is joseph's headline output and is **on by default**. Every agent narrates a
disciplined micro-cycle each turn — observe → interpret → trace → hypothesize → plan → act — streamed live to
**stderr**, tagged by role: `[reason:joseph:driver]`, `[reason:joseph:sqli]`, `[reason:joseph:auth]`, …

- No flag needed to see it; `--quiet-reasoning` turns off the live stream (still persisted).
- `--debug` adds the per-action trace (`joseph> <tool> <args>`), browser steps, and ZAP diagnostics.
- The full turn-by-turn record persists to `run.jsonl` (appended per turn). With a mounted workspace you can
  `tail -f joseph_run/run.jsonl` from the host in another terminal.

The stream is **per-turn**, not token-by-token: you see each agent's full thought as its turn completes. With
all lanes on it is a lot of interleaved output — the role tags tell you who is speaking; drop to `--analysts 3`
or `0` if it's too noisy.

---

## 7. The workspace (the bus)

Everything is persisted to `--out-dir`, and joseph reads it back mid-run:

```
joseph_<host>_<ts>/
  run.jsonl        # append-only per-turn: reasoning + narration + actions + result digests (the replay trace)
  leads.jsonl      # analyst leads → driver leases them (the cooperation channel)
  sessions/<id>/   # per-identity session material: cookies.txt, localStorage.json, sessionStorage.json, storage.json
  flows/           # captured request/response exchanges + screenshots
  js/              # the app's OWN JS bundles, saved as readable source
  scripts/         # every write_script source + its captured stdout/stderr
  tools/           # raw tool outputs, one file per call
  findings/        # confirmed findings + evidence
  REPORT.md        # final report: investigation narrative → findings (writeups) → leads → token cost
```

---

## 8. Scripting sandbox

When a built-in tool doesn't fit, joseph authors a script (`write_script`) and runs it (`run_script`) in the
container. Injected environment so a script acts **as the logged-in user** and its traffic is captured:

- `JOSEPH_TARGET`, `JOSEPH_HOST`, `JOSEPH_WORKSPACE`
- `JOSEPH_COOKIE`, `JOSEPH_BEARER` — the held session's material
- `HTTP_PROXY` / `HTTPS_PROXY` / `REQUESTS_CA_BUNDLE` — set when ZAP is up (so the script's traffic is captured)

Languages: **python** (`requests` preinstalled), **shell**, and **node** — a node script can
`require('crack-js')` directly (`NODE_PATH` is set image-wide). The language is remembered from `write_script`,
so `run_script` picks the right interpreter; name the file with a `.py`/`.sh`/`.js` extension to be safe.
`curl`, `git`, `python3`, and `node` are on PATH. Bounds: `--max-scripts` (default 25) and `--script-timeout`
seconds (default 120).

---

## 9. Wordlists & hash cracking on disk

Real paths joseph (and the tools/scripts) reference — there is **no** seclists/rockyou here:

| kind | path | notes |
|---|---|---|
| paths (breadth) | `/opt/boxcutter/boxcutter/data/wordlist.txt` | ~13k; `path-bust --full` |
| API routes | `/opt/boxcutter/boxcutter/data/api_wordlist.txt` | ~8k |
| dirb default | `/usr/share/dirb/wordlists/common.txt` | dir has `big.txt`, `vulns/`, … |
| dirsearch | `/usr/share/dirsearch/db/dicc.txt` | dirsearch's bundled list |
| subdomains | `/opt/boxcutter/boxcutter/data/subdomains.txt` | ~1k; dns-brute/dnsx default |
| passwords (fast) | `/opt/boxcutter/boxcutter/data/passwords_10k.txt` | ignis 10k |
| passwords (broad) | `/opt/boxcutter/boxcutter/data/passwords.txt` | hashmob 2025 |

Crack a **recovered** hash against a password list with **crack-js** (full details in
[crack-js.md](crack-js.md)):

```sh
node /usr/share/crack-js/crack.js <hash> /opt/boxcutter/boxcutter/data/passwords_10k.txt [mode]
```

This closes the chain: SQLi dump → `crack-js` → plaintext → credential reuse.

---

## 10. Traffic capture (ZAP)

joseph routes all traffic through a bundled ZAP daemon so the browser's own traffic and the binary tools'
traffic land in one capturable/mutatable store. If ZAP does not come up it falls back to cdp in-process capture
(the browser's traffic is still captured; the binary tools then rely on their own output). ZAP startup is
diagnosed to stderr (`zap ::` lines) — on failure it prints the tail of ZAP's own log so you can see why (heap,
port, missing Java). This is a graceful fallback, never fatal.

---

## 11. Token usage & cost

At the end of every run joseph prints a spend line to stderr and a **Token usage & cost** section in
`REPORT.md`:

```
joseph :: LLM spend - 812,004 in + 96,430 out = 908,434 tokens over 214 call(s)  ~$14.4571 USD (estimate; …)
```

Token counts are **exact** (read from each API response). The dollar figure is an **estimate** from a per-model
list-price table. For your exact gateway/Bedrock rate, set env vars (USD per 1M tokens):

```sh
-e BOXCUTTER_PRICE_IN=5 -e BOXCUTTER_PRICE_OUT=25
```

---

## 12. Safety model

Boundary-based, not allowlist-based: the container + the scope are the guardrail. joseph **may** POST/PUT/DELETE
**in scope** (it's authorised testing), and every mutation is logged. Egress is scope-limited. `--dry-run` maps
and predicts only, refusing all mutation — use it for a first look on a shared/live target.

---

## 13. Flag reference

| flag | default | meaning |
|---|---|---|
| `target` (positional) | — | optional app root; usually derived from `--context` |
| `--context TEXT` | — | the mission brief: goal + endpoints + auth |
| `--provider` | `anthropic` | `anthropic`/`openai`/`litellm`/`ollama` |
| `--model` | provider default | model id |
| `--api-key` | env | LLM key (or the provider's env var) |
| `--llm-proxy-url URL` | — | LLM gateway / endpoint |
| `--creds USER:PASS` | — | identity A form-login credentials |
| `--creds-b USER:PASS` | — | identity B (differential BOLA/BFLA) |
| `--login-url URL` | target | login page |
| `--analysts N` | all (9) | parallel read-only analyst lanes; 0 = driver only |
| `--analyst-steps N` | 40 | per-analyst step budget |
| `--max-rounds N` | 6 | soft replan budget |
| `--max-steps N` | 400 | hard cap on driver steps |
| `--max-scripts N` | 25 | cap on script runs |
| `--script-timeout S` | 120 | per-script wall-clock seconds |
| `--timeout S` | 45 | per-navigation/browser seconds |
| `--dry-run` | off | map + predict only, no mutation |
| `--quiet-reasoning` | off | stop streaming reasoning live (still logged) |
| `--out-dir DIR` | `joseph_<host>_<ts>` | workspace folder |
| `--report FILE` | — | also write REPORT.md to FILE |
| `--reasoning N` | 0 | (legacy) live-narration switch; the stream is on by default anyway |
| `-H "NAME: VALUE"` | — | extra request header, repeatable |
| `--table` | off | render findings as a table on stdout |
| `--debug` | off | per-action + browser + ZAP diagnostics to stderr |
| `--output/--jsonl/--json FILE` | — | save the result envelope |
| `--severity LEVELS` | all | filter reported findings |

---

## 14. Output

- **stdout:** the findings envelope (`--table` for a table). The full `REPORT.md` rides in the envelope's
  `extra.report`, so you always get it even without a mounted workspace.
- **`REPORT.md`:** investigation narrative (what was looked at, ruled out, confirmed) → each confirmed finding
  as a professional writeup (Summary → Steps → PoC → Impact → Remediation, with CWE + a CVSS heuristic,
  secrets masked) → open leads → analyst leads → token cost.
- **`run.jsonl`:** the full turn-by-turn reasoning + action trace.

---

## 15. Troubleshooting

| symptom | cause / fix |
|---|---|
| **Nothing printed for a while** | joseph calls the LLM gateway before its first status line — a hang here means the container can't reach the gateway. Check egress/DNS to `--llm-proxy-url`. |
| **`zap :: … did not become ready`** | ZAP didn't boot in time; joseph fell back to cdp capture (non-fatal). With `--debug` you get the tail of ZAP's own log — usually heap (`JMEM`), a missing JVM, or a slow/constrained container. |
| **Workspace is empty after the run** | `--out-dir` was written inside the container and not mounted. Mount a volume and point `--out-dir` at it (§2). The report still comes back on stdout regardless. |
| **`--out-dir` seems required** | it isn't — it defaults. You only need it (with a `-v` mount) to keep artifacts. |
| **Too much interleaved output** | `--analysts 3` (top lanes) or `--analysts 0` (driver only); or `--quiet-reasoning`. |
| **Cost figure looks off** | it's a list-price estimate; set `BOXCUTTER_PRICE_IN/OUT` to your real per-1M rate (§11). Token counts are exact. |

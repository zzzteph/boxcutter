"""Domain knowledge cheatsheets - the skill's judgment rubric, routed per specialist.

The boxcutter-pentest SKILL.md is one generalist that reads the whole `Classify` rubric. bob is a
team of specialists, so we EXTRACT that rubric into topic blocks and inject each into the agent that
needs it (same pattern as toolref: per-agent, focused, not the whole catalog). This is what makes an
agent score findings the way the skill does - concrete High/Medium/Suggestion criteria, evidence
bars, and false-positive discriminators - instead of guessing.

Source of truth: skill/boxcutter-pentest/SKILL.md `## Classify`. Keep in sync if that changes.
"""

from __future__ import annotations

_BLOCKS = {
    # The full judging rubric - the reporter is the single judge, so it gets all of it.
    "classify": """## Judgment rubric (classify EVERY finding; when unsure, omit)
Tiers: [VULN:High] directly exploitable (P1-P2) | [VULN:Medium] real but impact unclear/partial (P3) |
[SUGGESTION] concrete signal, not exploitable alone (P4) | (omit) noise. Unsure High vs Medium -> Medium.
Every finding needs verbatim, <=100-char, REDACTED evidence; no evidence -> SUGGESTION or omit.
- Exposed file: .env/.git/heapdump/backup with real content -> High; OpenAPI spec/phpinfo/placeholder ->
  SUGGESTION (a 401 on /actuator -> retry WITH a trailing slash before deciding).
- Unauth API 200: PII/financial/records/keys -> High; internal config/IPs -> Medium; a body that is ONLY an
  auth-rejection or 401/403/302->login -> omit; an auth-error body that ALSO leaks real data -> High.
- Admin: reachable controls with no login -> High; just a login form -> SUGGESTION. Test/debug path: reachable
  -> SUGGESTION; executes logic/returns data -> Medium.
- Injection: sqli (DB error naming table/col -> High; generic -> Medium) | ssti (7*7 renders 49 -> High) |
  lfi (file contents returned -> High) | rce (command output -> High) | xss (unescaped in text/html -> High;
  reflected only in JSON/plain -> omit) | nosql (auth bypass -> High; Mongo error -> Medium) | error-disclosure
  (creds -> High; stack trace only -> SUGGESTION) | time-blind (monotonic 1/3/5s -> Medium).
- Secrets: AWS AKIA.../Stripe sk_live.../private key/DB_PASSWORD+value -> High; JWT eyJ... -> Medium (check
  alg/claims); Google AIza... -> SUGGESTION; clearly public/test key -> omit.
- Anomalies: 500 + creds -> High; stack trace / SQL / field-names / internal path / debug-version header -> SUGGESTION.
- Chain correlated findings (info leak -> IDOR -> ATO) at the COMBINED severity.
- IGNORE (never a finding): missing security headers, clickjacking, CORS wildcards, cookie flags.""",

    "injection": """## Injection scoring (score every signal before you report it)
sqli: DB error naming a table/column -> High; generic error or boolean-only -> Medium.
ssti: 7*7 (or {{7*7}}) renders as 49 -> High.    lfi: real file contents returned -> High.
rce: command output appears in the response -> High.
xss: payload reflected UNESCAPED in a text/html response -> High; reflected only in JSON/plain -> OMIT (not exploitable).
nosql: auth bypass -> High; Mongo/driver error -> Medium.
error-disclosure: leaked credentials -> High; stack trace only -> SUGGESTION.
time-blind: response time scales monotonically with the injected delay (1s/3s/5s) -> Medium.
Evidence = the verbatim reflected payload / DB error / file line (<=100 chars). No evidence -> SUGGESTION or omit.""",

    "access": """## Access-control scoring
Unauth 200: PII/financial/records/keys -> High; internal config/IPs -> Medium; a body that is ONLY an
auth-rejection ({"error":"Unauthorized"}) or a 401/403/302->login -> OMIT (auth works). A 401 on
/actuator-style paths -> retry WITH a trailing slash first.
BOLA/IDOR: another owner's data returned across identities (diff a field like email/account-id, NOT status)
-> High; a byte-identical 200 for every id = public resource, not IDOR.
BFLA: a low-privilege identity reaching a privileged action -> High.
Business rules (single request): accepted negative amount / price-or-qty tamper / cross-tenant id / role-bypass
-> High or Medium by impact. Score access-control pass(sampled:N)|fail|partial - never a bare pass.
Anomalies: 500 + creds -> High; stack trace / field-names / internal path / debug-version header -> SUGGESTION.""",

    "exposure": """## Exposure scoring
.env / .git / heapdump / backup with real content -> High; an OpenAPI spec / phpinfo / placeholder -> SUGGESTION.
A 401 on /actuator (or similar) -> retry WITH a trailing slash before deciding.
Admin/management UI: reachable controls with no login -> High; just a login form -> SUGGESTION.
Test/debug endpoint: reachable -> SUGGESTION; executes logic or returns data -> Medium.""",

    "secrets": """## Secret scoring (always report the value REDACTED to pattern+location)
AWS AKIA... / Stripe sk_live... / private key / DB_PASSWORD with a value -> High.
JWT eyJ... -> Medium (note alg/claims).    Google API key AIza... -> SUGGESTION.
A clearly public/test key (publishable pk_..., example placeholder) -> omit.""",

    # Distilled from web-CTF / bug-bounty writeups - the recurring CHAINS, mapped to boxcutter actions.
    # Universal tradecraft (helps CTF and real targets): recover-then-exploit, pivot on every result.
    "chaining": """## Chaining & exploitation tradecraft (build a CHAIN, don't list bugs)
The win is almost always a CHAIN, not one isolated bug. After EVERY result ask "what does this UNLOCK?" - then
pivot to the next link. Never stop at the first signal when a further link is reachable.
RECOVER THEN EXPLOIT (precision beats blind fuzzing):
- exposed .git/.svn or a backup/source leak -> `git-extract` the FULL tree (or fetch the file) and READ the
  source: the exact SQL query, real routes, secret keys, how ids/tokens are built - then craft the PRECISE
  exploit instead of guessing.
- any file-read (LFI / path traversal) -> read the app's OWN source/config (index.php, config.php, .env,
  settings.py, web.config) to recover queries, creds, and hidden endpoints, then act on them immediately.
KNOWN CHAINS (see the left -> drive to the right):
- numeric `id=` / any reflected param -> SQL: `sqlmap <url>` then enumerate + UNION/--dump. SQLite: read
  `sqlite_master` for table/column names, then dump the interesting table; MySQL: use `information_schema`. A
  credential/key in a dumped row is the NEXT link, not the finish.
- verbose error / stack trace / debug page -> the exact path, query, framework or filename it names is your
  next probe target.
- a decoy/placeholder at an interesting path (an /admin that is a static image or a default welcome page) is a
  TELL, not a dead end - the real panel/route is hidden one level deeper or named in the source/JS; recover it.
- leaked/forgeable credential/JWT/cookie -> reuse it across the WHOLE authed surface (retry everything that
  401'd); decode the JWT for alg=none / weak secret / role claims to tamper.
- SSTI ({{7*7}}->49) / deserialization / file-upload -> escalate toward code execution; if it needs an RCE
  shell boxcutter lacks, report the CONFIRMED primitive + the exact manual next step (don't fake it).
GOAL ORIENTATION: if the target exposes a goal artifact (a flag, /flag.php, a secret/token table, an admin-only
record) that is the OBJECTIVE - reach it through the chain and quote it (redacted) as proof. On a real
(non-CTF) target there is no flag: the objective is the maximum-impact data the chain reaches - state the blast
radius.""",
}

# Per-specialist JUDGMENT cheatsheets (agents not listed judge nothing). Chaining is NOT here - it's
# universal (every agent both feeds and follows the chain) and added to all of them by for_agent().
_AGENT_TOPICS = {
    "reporter": ["classify"],                 # writes the report; needs the whole rubric
    "validator": ["classify"],                # the judge; needs the whole rubric to disprove
    "correlator": ["classify"],               # rates combined-severity chains
    "fuzzer": ["injection"],
    "access": ["access"],
    "api": ["injection", "access"],           # APIs are where injection + BOLA meet
    "graphql": ["injection", "access"],
    "exposure": ["exposure", "secrets"],
    "config-auditor": ["exposure"],
    "visual": ["exposure"],
    "fingerprint": ["exposure", "secrets"],
    "js-analyzer": ["secrets"],
    "business-logic": ["access"],
    "lateral": ["access", "secrets"],
}


def for_agent(name: str) -> str:
    """Chaining tradecraft is UNIVERSAL - every agent both feeds and follows the chain, so it leads every
    agent's knowledge; this specialist's judgment cheatsheet(s) follow."""
    topics = [t for t in _AGENT_TOPICS.get(name, []) if t != "chaining"]
    blocks = [_BLOCKS["chaining"]] + [_BLOCKS[t] for t in topics if t in _BLOCKS]
    return "\n\n".join(blocks)

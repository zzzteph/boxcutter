"""Tool reference - exact boxcutter flags + examples, injected per agent.

Each agent declares its own `tools` set; the base injects only the manual for those tools into its
system prompt (focused, not the whole catalog). Examples are shown as the bare boxcutter command
(tool name + args) - i.e. exactly the argv tokens to pass to run_boxcutter. Flags here are verified
against boxcutter/tools/*.py - keep them in sync if a tool's arguments change.
"""

from __future__ import annotations

# name -> manual block (usage + examples + the one gotcha that trips models up)
_REF = {
    "httpx": """httpx <domain|url>   - probe liveness; returns live URL(s) + status.
  e.g.  httpx example.com""",

    "http-request": """http-request <url> [-H "Name: Value"]... [-D "body"]   - GET, or POST when -D is given.
Returns {status, title, content, headers}. The response `headers` include Set-Cookie - that is how you log in.
  GET with auth:   http-request https://x/api/me -H "Authorization: Bearer T"
  FORM login:      http-request https://x/login -D "username=u&password=p"
                   then read headers.Set-Cookie in the result and REUSE it: -H "Cookie: session=..."
                   and report it under artifacts.tokens so later agents keep the session.
  JSON login:      http-request https://x/api/login -H "Content-Type: application/json" -D '{"u":"a","p":"b"}'
  GOTCHA: GET or POST ONLY - there is NO --method/-X flag; passing -D/--data is what makes it a POST. You CANNOT
  send OPTIONS/TRACE/HEAD/PUT/DELETE with this tool, so don't try `-X OPTIONS` (it just errors).""",

    "katana-crawl": """katana-crawl <url> [--js] [--params]   - crawl for links/endpoints.
  --js = only .js URLs | --params = only URLs with query params.
  e.g.  katana-crawl https://example.com""",

    "js-endpoints": """js-endpoints <js-url> [--base-url URL]   - extract API paths from a JS file.
  e.g.  js-endpoints https://example.com/static/app.js""",

    "dirsearch": """dirsearch <url>   - brute-force unlinked DIRECTORIES/paths under a base URL (it appends a
  wordlist to the path; it is NOT a file fetcher). Recurse by pointing at a found dir.
  e.g.  dirsearch https://example.com/        then  dirsearch https://example.com/admin/
  Run it together with `dirb` - they ship DIFFERENT wordlists, so each finds paths the other misses.
  DON'T point it at one known file (…/robots.txt, …/app.js) - that discovers nothing; fetch a file with http-request.""",

    "dirb": """dirb <url>   - directory brute-force with a DIFFERENT wordlist than dirsearch (complementary, NOT a substitute).
  Run it ALONGSIDE dirsearch on the same base so the two wordlists together cover more paths.
  e.g.  dirb https://example.com/""",

    "wayback": """wayback <domain> [--params] [--js] [--all] [--cc-indexes N]   - archived URLs from public indexes.
  --params = only URLs with params (best for fuzzing).
  e.g.  wayback example.com --params""",

    "screenshot": """screenshot <url>   - render a page (title/visual signal); use to spot open admin panels.
  e.g.  screenshot https://example.com/admin""",

    "browser-crawl": """browser-crawl <url> [--header ...]   - render a JS/SPA headless and capture routes +
every XHR/fetch API call a raw fetch misses. Use when the page is an empty shell.
  e.g.  browser-crawl https://example.com""",

    "browser-login": """browser-login <login-url> --creds user:pass   - perform a REAL login flow
(SPA/CSRF/redirect) and return the resulting cookie + bearer token.
  e.g.  browser-login https://example.com/login --creds admin:secret""",

    "browser-actions": """browser-actions <start-url> --action "verb:args" ...   - drive a real browser like a
human and capture XHR + final state (url/cookie/token). Repeatable & ordered, or --actions-file FILE.
  verbs: goto:URL | click:SEL | fill:SEL=VAL | type:SEL=VAL | select:SEL=VAL | press:SEL=KEY | check/uncheck:SEL |
         hover:SEL | scroll:bottom|top|X,Y | wait:MS | waitfor:SEL | eval:JS
  SEL:   id=x -> #x | name=x -> [name="x"] | text=Foo | css=... | raw CSS
  e.g.  browser-actions https://x/login --action "fill:#user=admin" --action "fill:#pass=pw" --action "click:text=Log in" """,

    "nuclei": """nuclei <url> [--opt-args "<native nuclei flags>"] [--severity critical,high] [-H "Name: Value"]
  --opt-args passes raw nuclei flags (e.g. -tags, -t).
  e.g.  nuclei https://example.com --opt-args "-tags exposure,misconfig,cve,kev,panel" --severity critical,high""",

    "git-extract": """git-extract <url>   - dump an exposed .git (point at the dir that holds /.git).
  e.g.  git-extract https://example.com/panel/""",

    "scan-secrets": """scan-secrets <url>   - find secrets (returned REDACTED) in a JS/text resource.
  e.g.  scan-secrets https://example.com/static/app.js""",

    "swagger-specs": """swagger-specs <host>   - discover OpenAPI/Swagger spec URLs for a host.
  e.g.  swagger-specs example.com""",

    "swagger-parser": """swagger-parser <spec-url>   - parse a spec into its endpoints/metadata.
  e.g.  swagger-parser https://example.com/openapi.json""",

    "swagger-endpoints": """swagger-endpoints <spec-url> [--fuzzable] [-H "Name: Value"]   - list endpoints from a spec.
  --fuzzable emits {FUZZ}-marked variants to hand straight to `fuzz`.
  e.g.  swagger-endpoints https://example.com/openapi.json --fuzzable""",

    "graphql-detect": """graphql-detect <host>   - locate GraphQL endpoints.
  e.g.  graphql-detect example.com""",

    "graphql-audit": """graphql-audit <url>   - introspection / batching / arg-injection checks on a GraphQL endpoint.
  e.g.  graphql-audit https://example.com/graphql""",

    "fuzz": """fuzz <url> [--method GET|POST] [--data "...{FUZZ}..."] [-H "Name: Value"]... [--payload "<p>" --pattern "REGEX"]
Markers: {FUZZ} = inject here | {NUMBERS} / {NUMBERS[m-n]} = enumerate numeric IDs (IDOR) | unmarked = inject
every query param + ID-like path segment. Self-confirming (re-fires its own hits). Covers XSS/SQLi/SSTI/LFI/
RCE/XXE/NoSQL/GraphQL/error-disclosure + time-blind.
  query/path:  fuzz "https://x/product?id=1"            xss param:  fuzz "https://x/search?q={FUZZ}"
  JSON body:   fuzz "https://x/api/users" --method POST -H "Content-Type: application/json" --data '{"name":"{FUZZ}"}'
  IDOR scan:   fuzz "https://x/api/orders/{NUMBERS}"
  precise re-check (use in verify): fuzz "https://x/p?q=1" --payload "<svg onload=alert(1)>" --pattern "onload=alert" """,

    "sqlmap": """sqlmap <url> [<native sqlmap flags>] [-H "Name: Value"]   - confirm AND exploit SQLi.
  Pass sqlmap's OWN flags straight through (they are forwarded verbatim); the base run already applies
  --batch --random-agent --level 1 --risk 1, so don't repeat those. Auth goes through -H, not --cookie.
  confirm + fingerprint:  sqlmap "https://x/p?id=1" --banner --current-user --current-db --dbs
  EXTRACT DATA (required to confirm real impact): list then dump -
        sqlmap "https://x/p?id=1" --tables             (find table names)
        sqlmap "https://x/p?id=1" --dump -T users      (dump a table's rows)
  if id=1 isn't flagged, go deeper:  sqlmap "https://x/p?id=1" --level 3 --risk 2 --technique=BEUST --dbs
  with a harvested session:  sqlmap "https://x/p?id=1" -H "Cookie: PHPSESSID=abc" --tables """,
}

# canonical order so the block reads recon -> exploit
_ORDER = [
    "httpx", "katana-crawl", "js-endpoints", "dirsearch", "dirb", "wayback", "screenshot",
    "browser-crawl", "browser-login", "browser-actions",
    "swagger-specs", "swagger-parser", "swagger-endpoints", "graphql-detect", "graphql-audit",
    "nuclei", "git-extract", "scan-secrets", "fuzz", "sqlmap", "http-request",
]


def reference_for(tools) -> str:
    """Render the manual for just the tools this agent uses (empty if none are documented)."""
    blocks = [f"### {name}\n{_REF[name]}" for name in _ORDER if name in tools and name in _REF]
    if not blocks:
        return ""
    return "## Tool reference - exact flags + examples (pass these tokens to run_boxcutter)\n" + "\n\n".join(blocks)

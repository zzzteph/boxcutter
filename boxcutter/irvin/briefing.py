"""Turn the operator's free-text --context into structured run RULES.

A user finds it easier to describe the engagement in plain language than to remember a wall of flags, so this
lets the briefing itself carry settings: "test *.example.com, it's a SPA with an API on api.example.com, creds
are user:pass, send Tester-Token: abc to skip recaptcha, focus on checkout, /admin is out of scope". One LLM
pass reads that and returns the scope host-patterns, the request headers to send on every call, the login
credentials, and a cleaned focus.

Secrets matter here: a header/token or credential the operator mentions is EXTRACTED into its private channel
(headers -> the runner's global headers; creds -> the stored-credential placeholder mechanism, same as
--creds) and REMOVED from the focus that gets broadcast into every agent prompt - so putting a secret in
--context stops being a leak and becomes a convenience. Best-effort: any parse/provider failure just falls
back to using the raw briefing as-is, with no rules applied.
"""

from __future__ import annotations

from .context import extract_json

_SYS = (
    "You extract structured RUN RULES for a web/API penetration test from an operator's free-text briefing. "
    "Return ONE json object, nothing else:\n"
    '{"scope": ["host or *.wildcard the operator said to include"],\n'
    ' "headers": ["Exact-Header: value the operator said to send on every request"],\n'
    ' "creds": [{"label": "A", "user": "email-or-username", "password": "the password", "login_url": ""}],\n'
    ' "out_of_scope": ["paths/areas the operator said NOT to touch"],\n'
    ' "focus": "a faithful rewrite of the briefing - what the target IS, what to focus on, what is out of '
    'scope - with EVERY secret VALUE removed (say \'credentials are provided\' / \'a Tester-Token is set\', '
    'never the password/token itself)"}\n'
    "RULES: extract ONLY what the operator actually stated - never invent a host, header, credential, or token. "
    "`scope` is HOSTS only (a bare domain, or a *.domain wildcard for a whole domain), never paths or URLs. "
    "`headers` is any request header/bypass/auth token to send on EVERY request (Tester-Token, Authorization, "
    "X-Api-Key, a Cookie) as \"Name: value\". `creds` is any LOGIN credential the operator gave (often written "
    "\"creds are user:pass\" or \"login with X / password Y\"): label \"A\" for the first/primary identity, "
    "\"B\" for a second one; user is the email/username, password is the secret, login_url is the login page "
    "if one was stated else empty. If the briefing names no hosts/headers/creds/exclusions, return empty lists. "
    "`focus` must NOT contain any password or token you put in `creds`/`headers`. Output only the json.")


def parse(provider, context: str, base_host: str) -> dict:
    """Parse the briefing into {scope, headers, out_of_scope, focus}. Empty dict if there's nothing to parse
    or the provider call fails - the caller then just uses the raw context."""
    context = (context or "").strip()
    if not context:
        return {}
    user = (f"BASE HOST (the target): {base_host}\n\nOPERATOR BRIEFING:\n{context}\n\n"
            "Extract the run rules as the json object.")
    try:
        raw = provider.chat(_SYS, user)
    except Exception:  # noqa: BLE001 - a briefing we can't parse must not break the run
        return {}
    obj = extract_json(raw)
    if not isinstance(obj, dict):
        return {}

    def _strs(key):
        return [s.strip() for s in obj.get(key, []) if isinstance(s, str) and s.strip()]

    scope = [h.lower() for h in _strs("scope")]
    headers = [h for h in _strs("headers") if ":" in h]       # a real header is "Name: value"
    creds = []
    for c in obj.get("creds", []) or []:
        if isinstance(c, dict) and str(c.get("user") or "").strip() and str(c.get("password") or ""):
            creds.append({"label": (str(c.get("label") or "A").strip().upper()[:1] or "A"),
                          "user": str(c["user"]).strip(),
                          "password": str(c["password"]),
                          "login_url": str(c.get("login_url") or "").strip()})
    focus = obj.get("focus") if isinstance(obj.get("focus"), str) else ""
    return {"scope": scope, "headers": headers, "creds": creds,
            "out_of_scope": _strs("out_of_scope"), "focus": focus.strip()}

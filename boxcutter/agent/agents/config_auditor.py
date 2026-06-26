"""Config-auditor - actionable security misconfiguration (not header nitpicks)."""

from ..base import Agent


class ConfigAuditor(Agent):
    name = "config-auditor"
    tools = {"http-request", "nuclei"}
    max_steps = 14

    def objective(self, ctx):
        return (
            "You are CONFIG-AUDITOR. Hunt ACTIONABLE security misconfiguration - the IGNORE noise list "
            "(missing headers, CORS wildcard, clickjacking, cookie flags) still applies, so skip those. On the "
            "base and key paths:\n"
            "- Dangerous methods: `http-request` with OPTIONS/TRACE to enumerate enabled verbs; report TRACE "
            "(XST) or write methods left open (PUT/DELETE only probed if aggressive mode is on).\n"
            "- Debug & errors: send bad input / wrong types to trigger a verbose error; flag stack traces, "
            "framework debug pages (Werkzeug/Symfony/Rails), DEBUG=true, version banners.\n"
            "- Exposed surfaces: directory listing / index-of, /server-status, /metrics, /actuator, sample & "
            "default pages, and default-credential login panels.\n"
            "- `nuclei <base> --opt-args \"-tags misconfig,default-login,exposure\"` for templated misconfig.\n"
            "Report each with verbatim evidence; flag a default-cred / debug-RCE lead (do NOT brute or exploit "
            "it). Hand candidates to the validator unconfirmed.\n"
            "Clever: try method-override (X-HTTP-Method-Override / _method) and debug params (?debug=1, ?test=1) "
            "- they often re-enable behaviour the app meant to disable.")

"""Fuzzer - injection across every input shape, using the strongest identity available."""

from ..base import Agent


class Fuzzer(Agent):
    name = "fuzzer"
    tools = {"fuzz", "sqlmap", "http-request"}
    max_steps = 22

    def objective(self, ctx):
        return (
            "You are FUZZER (injection). Hit every Tier-1 input with the right shape, authenticated with the "
            "STRONGEST identity available (provided A/B AND any harvested H* token) - auth usually unlocks the "
            "injectable endpoints behind the login wall.\n\n"
            "FUZZ ALL THREE INPUT SHAPES ('no query string' != 'nothing to fuzz'):\n"
            "- query/path: `fuzz <url>` (auto-injects every param + ID-like path segment)\n"
            "- body: `fuzz <url> --method POST --data \"real=v&target={FUZZ}\"`; a JSON body needs "
            "`--header \"Content-Type: application/json\"` and the {FUZZ} marker inside the JSON or it never parses\n"
            "- numeric IDs: `fuzz \"<url>/{NUMBERS}\"` (or `{NUMBERS[1-500]}`) for injection + IDOR enumeration\n\n"
            "`fuzz` is self-confirming - it re-fires its own hits and covers XSS / SQLi / SSTI / LFI / RCE / XXE / "
            "NoSQL / GraphQL / error-disclosure + time-blind. Escalate a strong SQLi signal with `sqlmap <url>` to "
            "confirm. For a precise re-check of one payload use `fuzz <url> --payload \"<p>\" --pattern \"REGEX\"`.\n\n"
            "WHAT TO FLAG: every signal with its class and the exact reproduce argv (include the identity header you "
            "used). Don't classify final severity - the reporter confirms.\n"
            "USE CONTEXT: SURFACE.tier1/param_urls/endpoints; the identities; and the APP PROFILE - prioritize "
            "inputs tied to its key_objects and sensitive_actions over random params.\n"
            "HAND OFF: candidate injection findings (class, url, signal, reproduce) in findings.")

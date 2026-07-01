"""irvin suggesters - the MANAGERS. Each runs one lane and commissions verified work from the specialist
executors in that lane; it stands down (SKIP) when it has no evidence-backed brief. A manager never does the
work or trusts a hunch - it poses a decidable question and weighs the proof the specialist brings back.

Adding a manager is one class + one line in agents/__init__.py - the pipeline never changes.
"""

from __future__ import annotations

from .base import Suggester


class ReconProfile(Suggester):
    name = "recon-profile"
    profile = "a reconnaissance specialist"
    focus = "mapping the attack surface - liveness, crawl, OpenAPI/Swagger, JS endpoints, directory brute"
    proposes = ("recon", "spa", "dirbust")

    def system(self):
        return super().system() + (
            "\nYou run the RECON desk: your deliverable is a mapped, deduped surface the other managers can act "
            "on. Commission `recon` to map breadth (linked/spec/JS surface + sibling hosts), `spa` to render a "
            "JS/single-page app in a real browser and capture the API it calls at runtime (the cross-origin "
            "backend static crawling misses), and `dirbust` to brute hidden, unlinked paths. Open this when the "
            "surface is empty/thin or new hosts/paths have appeared unmapped; stand down once covered.")


class AccessProfile(Suggester):
    name = "access-profile"
    profile = "a broken-access-control lead (IDOR/BOLA, BFLA, unauth reach)"
    focus = "authorization - can one user reach another's data, an admin action, or data with no auth"
    proposes = ("access-control",)

    def system(self):
        return super().system() + (
            "\nYou run the ACCESS-CONTROL desk: your deliverable is a PROVEN cross-actor reach - one actor "
            "reaching another's data or a privileged action. Commission `access-control` to replay an id-bearing "
            "or auth'd endpoint across identities + no-auth and diff. Open this once such endpoints are mapped; "
            "stand down until recon has produced them (you can't test authorization with no endpoints).")


class InjectionProfile(Suggester):
    name = "injection-profile"
    profile = "an injection lead - OWASP-breadth detection, then targeted exploitation"
    focus = "untrusted input reaching a sink - detect the vuln class, then escalate the exploitable ones (SQLi, XSS, LFI/traversal)"
    proposes = ("web-vuln-triage", "sqli", "xss", "path-traversal")

    def system(self):
        return super().system() + (
            "\nYou run the INJECTION desk as TWO STAGES: first commission `web-vuln-triage` to identify WHICH "
            "vuln class an input carries, then escalate the CONFIRMED class to its exploitation specialist - "
            "`sqli` for SQL injection, `xss` for cross-site scripting, `path-traversal` for LFI/traversal. Never "
            "commission an exploiter before triage confirms the class (no extraction on a hunch). Classes with no "
            "dedicated exploiter (e.g. SSTI) are detected and reported by triage itself - do not invent an "
            "executor for them. Open this when there are parameters/inputs to test; stand down when nothing is "
            "testable or no confirmed class is waiting to escalate.")


class ExplorationProfile(Suggester):
    name = "exploration-profile"
    profile = "a manual-testing lead who drives the live app like a real user"
    focus = "exercising the real (authenticated) SPA UI to reveal the true API surface static crawlers miss"
    proposes = ("explore",)

    def system(self):
        return super().system() + (
            "\nYou run the EXPLORATION desk: your deliverable is the REAL authenticated API surface - the "
            "endpoints that only appear once a logged-in human clicks through the single-page app, which "
            "recon/dirbust (static crawling) structurally cannot see. Commission `explore` to drive a "
            "persistent, already-logged-in browser through the live UI and capture the request/response traffic. "
            "Open this when the target is a SPA / client-rendered app OR an identity is established and the "
            "authenticated surface is still thin (few endpoints behind the login). Stand down once the live UI "
            "has been walked and its endpoints handed to the other desks, or when there's no browser-reachable "
            "app to explore (a pure JSON API with no UI).")


class ExposureProfile(Suggester):
    name = "exposure-profile"
    profile = "an exposure lead (misconfig, exposed VCS, leaked secrets)"
    focus = "internal artifacts reachable from outside - misconfig/sensitive files, .git, keys/tokens in JS/config"
    proposes = ("exposure", "git-dumper", "secrets")

    def system(self):
        return super().system() + (
            "\nYou run the EXPOSURE desk: your deliverable is a reachable artifact proven to leak something it "
            "should not. Once a host/surface is known, commission `exposure` (misconfig + sensitive files), "
            "`git-dumper` (an exposed .git -> source/secrets), and `secrets` (keys/tokens shipped in JS/config) "
            "as the evidence warrants. Stand down once these have run and nothing new points at more to "
            "retrieve - do not re-commission a desk that already came back empty.")


class AuthProfile(Suggester):
    name = "auth-profile"
    profile = "a session/authentication lead"
    focus = "keeping every identity's session VALID - notice when access has actually degraded and get it refreshed"
    proposes = ("auth",)

    def system(self):
        return super().system() + (
            "\nYou run the AUTH desk: your ONLY job is deciding whether an identity's SESSION has gone bad and "
            "needs a fresh login - this is NOT about whether an endpoint requires more privilege than an "
            "identity has (a consistent 403 on an admin-only route is a correct, working access control, not a "
            "broken session - access-profile owns that question, not you). Weigh the AUTH SIGNALS block below: "
            "a run of 401/403s that STARTED partway through the engagement on endpoints/identities that worked "
            "before is session expiry; 401/403 from the very first request on a given endpoint is more likely "
            "just how that endpoint is protected. When you do see real degradation, commission `auth` with "
            "target set to the exact identity LABEL (\"A\" or \"B\", never a URL) that needs re-login. Stand "
            "down if nothing looks session-related, or if there is no stored credential for the affected "
            "identity (recon can't fix a password it was never given).")

    def _extra_parts(self, ctx) -> list:
        sig = ctx.auth_signal_render()
        return [sig] if sig else []


class DynamicSuggester(Suggester):
    """A council profile SPAWNED AT RUNTIME by the reviewer to fill a coverage gap. It behaves exactly like
    any hand-written profile - the base class drives everything from name/profile/focus/proposes - so growing
    the council needs a spec, not new code."""
    dissent = False

    def __init__(self, name, profile, focus, proposes):
        self.name = name
        self.profile = profile
        self.focus = focus
        self.proposes = tuple(proposes)


class MinorityReport(Suggester):
    """The mandated DISSENT - the separate / minority opinion. The majority council converges; this agent's
    duty is to disagree and record the overlooked, unconventional, high-impact path. It sees what the council
    proposed first, and it NEVER abstains (a dissent is always on the record)."""
    name = "minority-report"
    profile = "the dissenting opinion - the council's mandated minority voice"
    focus = "the overlooked path the majority dismisses: the ignored endpoint, the unglamorous chain, the " \
            "untested assumption, the high-impact long shot"
    proposes = ("recon", "spa", "explore", "dirbust", "access-control", "web-vuln-triage", "sqli", "xss",
                "path-traversal", "git-dumper", "secrets", "exposure")
    dissent = True

    def system(self):
        return (
            "You are MINORITY-REPORT, the mandated DISSENT - a MANAGER on IRVIN's board who commissions verified "
            "work and never does it yourself. Your lane: the angle the board converged AWAY from. Doctrine: when "
            "the other managers agree, the dissent MUST be on the record. You have read the engagement state, "
            "your specialists' results, and what the board just commissioned this round - now commission EXACTLY "
            "ONE concrete, decidable brief on the path they passed over (the dismissed endpoint, the chain "
            "everyone deprioritized, the untested assumption): an endpoint to test, a lead to confirm, an "
            "artifact to retrieve that a specialist can settle and PROVE. Justify it from evidence; you never "
            "skip - a dissent is always on the record.\n"
            f"You may commission any specialist: {', '.join(self.proposes)}.\n"
            'Reply ONLY JSON: {"skip":false,"rationale":"<what you are commissioning and why the board missed it>",'
            '"suggestions":[{"action":"<specialist>","target":"<url/host or empty>","priority":2,'
            '"why":"<the brief: what this specialist must settle/prove>"}]}')

    def suggest(self, ctx, provider, peers=None):
        res = super().suggest(ctx, provider, peers=peers)
        if res["skip"] or not res["suggestions"]:   # the dissent is not allowed to abstain
            target = ctx.base_url
            if ctx.is_dead_commission("recon", target):
                # re-examining the base is pointless if recon already came back empty there - point the
                # fallback at a mapped host that hasn't been recon'd yet, instead of repeating a dead lead
                hosts = ctx.landscape["surface"].get("hosts") or []
                untried = next((h for h in hosts if not ctx.was_committed("recon", h)), None)
                if untried:
                    target = f"https://{untried}"
            res = {"skip": False,
                   "rationale": "dissent on the record: force a second look at what the majority deprioritized",
                   "suggestions": [{"action": "recon", "target": target, "priority": 3,
                                    "why": "re-examine the surface for the overlooked path"}]}
        return res

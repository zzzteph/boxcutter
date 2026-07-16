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
            "or auth'd endpoint across identities + no-auth and diff. Pick up any OPEN LEAD tagged "
            "bola/bfla/access another desk raised. Open this once such endpoints are mapped; stand down until "
            "recon has produced them. (A merely EXPOSED admin/login panel is EXPOSURE's to report, not yours - "
            "you own proving a cross-actor/privileged REACH, not cataloguing that a panel exists.)\n"
            "STAY IN LANE: your brief is AUTHORIZATION only. Do NOT commission file-inclusion (/etc/passwd, "
            "'../') or SQLi/XSS probing - that is path-traversal's / the injection desk's job. If an endpoint "
            "looks injectable or file-read-y, leave it to them (the executor will raise a lead); don't fold it "
            "into an access-control brief.\n"
            "COVERAGE IS YOURS: the COVERAGE MAP lists the object-referencing families (an {id} in the path or "
            "an id-like param) that `access-control` has NOT yet tested (its OWED line). Work them until your "
            "lane reads COMPLETE or you can justify skipping one - an untested id-bearing endpoint is an "
            "unchecked IDOR/BOLA.")


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
            "testable or no confirmed class is waiting to escalate.\n"
            "COVERAGE IS YOURS: the COVERAGE MAP lists the input-bearing families `web-vuln-triage` has NOT yet "
            "tested (its OWED line). Those untested families are your unfinished work - keep commissioning triage "
            "over them until your lane reads COMPLETE, or you can justify skipping a specific family. Don't leave "
            "an input-bearing endpoint untested just because it wasn't the loudest lead.")


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
    proposes = ("exposure", "git-dumper", "secrets", "dirbust")

    def system(self):
        return super().system() + (
            "\nYou run the EXPOSURE desk: your deliverable is a reachable artifact proven to leak something it "
            "should not. Once a host/surface is known, commission `exposure` (misconfig + sensitive files), "
            "`git-dumper` (an exposed .git -> source/secrets), and `secrets` (keys/tokens shipped in JS/config) "
            "as the evidence warrants. A newly-discovered admin/management panel (surface tagged 'panel', e.g. "
            "/admin, or a `panel` lead raised for you) is YOURS - point `exposure` at it to report the reachable "
            "interface (login-gated = Low, an unauthenticated working console = High), even if exposure already "
            "ran on other paths. Exposure OWNS the panel report end to end.\n"
            "LEVERAGE A DISCOVERED DIRECTORY - don't stop at the surface page. A found directory (an admin/"
            "management/app folder like /admin) is NEW SURFACE to enumerate, not a terminal report. When YOU "
            "JUDGE one worth it - a panel/app directory, NOT every /css//js//static asset folder - commission "
            "`dirbust` to recurse INSIDE it (enumerate /admin/ for subpaths, hidden files, a real panel) and "
            "`git-dumper` to check for an exposed repo UNDER it (/admin/.git/ -> source -> secrets/creds). A "
            "source leak is frequently ONE DIRECTORY DEEP, not at the web root, so a bare 'nginx welcome page' "
            "at /admin is a reason to dig, not to close it out. Use judgment: dig the interesting directories, "
            "don't brute every folder. KEEP CHAINING: this is recursive - when a dig surfaces a DEEPER directory "
            "(dirbust /admin/ reveals /admin/panel/), that new directory is itself UN-dug; commission `dirbust` "
            "on IT and `git-dumper` on <it>/.git too. Reporting a panel is NOT the same as having searched "
            "inside it, so do NOT stand down as 'all characterized' while any discovered directory - especially "
            "a login panel like /admin/panel/ - has not yet been dirbusted INTO.\n"
            "Stand down once these have run and "
            "nothing new points at more to retrieve - do not re-commission a desk that already came back empty.")


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
            "identity (recon can't fix a password it was never given).\n"
            "SEPARATELY, an exposed admin/login panel (e.g. /admin, anything the surface tags 'panel') with NO "
            "supplied credential is worth a BOUNDED default-credential check: commission `auth` with the panel "
            "URL and a note to try only a handful of well-known PUBLIC defaults (admin/admin, root/root, ...), "
            "never a brute-force. A success is a weak-credentials finding; a miss is fine. Do it ONCE per "
            "panel - don't re-commission a panel that already came back clean.")

    def _extra_parts(self, ctx) -> list:
        sig = ctx.auth_signal_render()
        return [sig] if sig else []


class PostExploitationProfile(Suggester):
    name = "post-ex-profile"
    profile = "a post-exploitation lead"
    focus = "turning a CONFIRMED foothold into real impact - reusing what a proven vuln yields (dumped " \
            "credentials, readable files, DB access) to reach the actual objective: authenticated areas, admin " \
            "functionality, and the sensitive data behind them"
    proposes = ("auth", "access-control", "explore", "sqli", "path-traversal", "dirbust", "git-dumper", "exposure")

    def system(self):
        return super().system() + (
            "\nYou run the POST-EXPLOITATION desk: your job STARTS where a vuln is already PROVEN. The other "
            "desks stop at 'confirmed SQLi/LFI/access'; your duty is to make sure the engagement doesn't END "
            "there. Read the CONFIRMED findings and ask: what does this foothold UNLOCK that we have NOT taken "
            "yet? Common pivots:\n"
            "  - a SQLi/LFI that dumped a PLAINTEXT CREDENTIAL (login + password) -> commission `auth` to LOG IN "
            "with that recovered credential and establish an identity, so the authenticated desks reach what it "
            "opens (an admin panel, a user's data). A dumped value that is only a HASH is NOT directly reusable "
            "here - note it and move on; do not attempt to crack it.\n"
            "  - DB access already proven -> commission `sqli` to pull the SPECIFIC target (a flag / secret / "
            "config / token table), NOT to re-dump what has already been extracted.\n"
            "  - a confirmed arbitrary file read -> commission `path-traversal` to read the specific high-value "
            "file (app config, key, flag) rather than re-proving the read.\n"
            "  - a discovered DIRECTORY/panel (e.g. an exposed /admin, even a bare 'nginx welcome page') -> "
            "commission `dirbust` to enumerate INSIDE it and `git-dumper` to pull an exposed repo UNDER it "
            "(/admin/.git/ -> source code -> secrets/creds): a source/secret leak is often one directory deep. "
            "Chain the discovery into deeper compromise instead of letting it end as a surface report.\n"
            "Open this ONLY when a high-impact vuln is CONFIRMED but its payoff (authenticated access, the admin "
            "panel, the target secret/flag) has not yet been reached. Stand down once the foothold has been "
            "driven to its objective, or there is genuinely nothing further to reach. NEVER re-run an extraction "
            "that already succeeded - only commission a pivot that advances toward something NEW.")


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

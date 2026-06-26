"""Visual - headless screenshots: open admin UIs and visually-confirmed XSS."""

from ..base import Agent


class Visual(Agent):
    name = "visual"
    tools = {"screenshot", "http-request", "browser-actions"}
    max_steps = 10

    def should_run(self, ctx):
        # only on the full image (screenshot binary present after capability-prune) and with somewhere to look
        return "screenshot" in self.tools and bool(ctx.base_url or ctx.surface.get("paths"))

    def objective(self, ctx):
        return (
            "You are VISUAL. Use `screenshot` (headless render) to SEE what text-only checks miss:\n"
            "- Screenshot the root and every admin / login / dashboard / console / management path on the surface. "
            "Flag a management UI that loads its CONTROLS with NO login (High) vs just a login form (Suggestion), "
            "and any sensitive data rendered without auth.\n"
            "- For a candidate reflected/stored XSS, screenshot the payload URL to confirm it actually RENDERS / "
            "executes in a browser - that turns a maybe into a confirmed finding.\n"
            "- Note SPA shells that render data client-side (a hint to where the real API + its auth live).\n"
            "Report open management UIs and visually-confirmed XSS with the rendered title/evidence. If screenshot "
            "is unavailable in this image, say so in artifacts.notes and stop.\n"
            "Clever: diff the authed vs unauthed render, and catch a 'flash' of sensitive content shown briefly "
            "before a client-side auth redirect.")

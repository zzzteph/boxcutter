"""Browser - renders JS/SPA apps so the testers see the real surface, not an empty shell."""

from ..base import Agent


class Browser(Agent):
    name = "browser"
    tools = {"browser-crawl", "browser-actions", "browser-login", "http-request"}
    max_steps = 10

    def should_run(self, ctx):
        # only when the browser tool is actually installed (capability-pruned otherwise)
        return "browser-crawl" in self.tools and bool(ctx.base_url)

    def objective(self, ctx):
        return (
            "You are BROWSER. Many apps are JS/SPA: a raw fetch returns an empty shell, so the real routes and "
            "API calls only appear once the page runs. Render them:\n"
            "- `browser-crawl <base>` to load the app, capture every XHR/fetch (the real API surface) and the "
            "same-origin routes, and click through a bounded set of elements to trigger more.\n"
            "- If the surface already looks rich (lots of server-rendered links) this may add little - that's fine.\n"
            "Put every captured XHR endpoint and route in artifacts.endpoints so recon-ranker, api, fuzzer and "
            "access test the ACTUAL endpoints instead of the shell. Note in artifacts.notes whether the target is "
            "a JS/SPA app (so the report reflects true coverage).\n"
            "Clever: trigger lazy-loaded routes (scroll / open menus) and capture request BODIES (param names) not "
            "just URLs, and note any websocket or GraphQL traffic the render reveals.")

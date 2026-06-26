"""Discovery - maps and ranks the attack surface; recurses into interesting paths."""

from ..base import Agent


class Discovery(Agent):
    name = "discovery"
    tools = {"httpx", "subfinder", "katana-crawl", "js-endpoints", "dirsearch", "dirb", "wayback", "browser-crawl"}
    max_steps = 20

    def objective(self, ctx):
        wb = ("4. `wayback <domain> --params` for archived parameter URLs the live site no longer links.\n"
              if ctx.mode == "complete" else "")
        return (
            "You are DISCOVERY. Build the attack surface the whole pipeline tests, and PIVOT on what you find - "
            "this is adaptive recon, not a fixed list.\n\n"
            "PLAYBOOK:\n"
            "1. `katana-crawl <base>` for links, forms, and endpoints; pull every JS URL it finds.\n"
            "2. `js-endpoints <jsfile>` on each JS file - JS often hides the real API paths, admin routes, and "
            "param names that no page links to.\n"
            "3. `dirsearch <base>` for unlinked dirs/files; when you hit an interesting dir (admin, panel, api, "
            "backup, upload, .git, .svn), dirsearch INTO it to go deeper - recurse, don't stop at depth 1.\n"
            f"{wb}"
            "5. (bare domain) `subfinder <domain>` for more hosts to fold into scope.\n\n"
            "RANK the surface into tiers and act on Tier-1 first:\n"
            "- Tier 1 (where bugs live): auth/admin, `?id=`/numeric-id endpoints, /api & /v1, OpenAPI/Swagger "
            "specs, GraphQL, file-upload, anything taking user input or an object id.\n"
            "- Tier 2: other dynamic pages. Tier 3: static assets - skip.\n\n"
            "USE CONTEXT: the BASE url and entry shape from the planner; don't re-confirm liveness.\n"
            "HAND OFF: put Tier-1 URLs plus every spec / GraphQL / admin / panel / .git / upload URL in "
            "artifacts.endpoints (later agents act on exactly these); summarize counts and the notable paths + any "
            "stack hints you saw in artifacts.notes.\n"
            "Clever: set a soft-404 baseline (request a random path) to separate real hits from catch-alls; mine "
            "params from JS + wayback, not just paths; check robots.txt / sitemap.xml / .well-known; and prefer "
            "versioned API roots (/v1, /v2 - older versions are often less guarded).")

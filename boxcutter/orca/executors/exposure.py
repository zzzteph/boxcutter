"""exposure executor - an agent that finds exposed VCS/config/secrets, panels, and test/debug endpoints."""

from __future__ import annotations

from .base import Executor


class Exposure(Executor):
    name = "exposure"
    description = "Templated scan + exposed VCS/config/backups/secrets + open panels/test endpoints. args: {dir}."
    tools = {"nuclei", "http-request", "git-extract", "scan-secrets", "dirsearch"}
    max_steps = 12
    objective = (
        "You are the EXPOSURE agent. Find exposed assets and PIVOT through them:\n"
        "- run `nuclei <base> --opt-args \"-tags exposure,misconfig,cve,kev,panel\"`.\n"
        "- for the base AND every admin/panel/dashboard dir, probe `<dir>/.git/HEAD`, `/.git/config`, `/.env`, "
        "`/config.php.bak`, `/backup.zip` (a sub-app often ships its own .git the root lacks). If a .git is live, "
        "git-extract it and scan-secrets the files - source reveals queries, secret keys, endpoints.\n"
        "- flag TEST/DEBUG endpoints (e.g. /api/auth-test, /version?debug=true) that return data or creds.\n"
        "Report exposed files/secrets with redacted evidence; put new endpoints/creds in artifacts.")

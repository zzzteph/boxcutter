"""exploiter executor - an agent that confirms+extracts injection/source leads (sqlmap, LFI, .git)."""

from __future__ import annotations

from .base import Executor


class Injector(Executor):
    name = "sqlmap"
    description = "Confirm and EXTRACT a SQLi (or mine an LFI/exposed-source lead). args: {url}."
    tools = {"sqlmap", "http-request", "fuzz", "git-extract", "scan-secrets"}
    max_steps = 12
    objective = (
        "You are the EXPLOITER agent. For the lead in your task, extract real impact:\n"
        "- SQLi: run sqlmap with native flags - `--dbs`/`--tables` then `--dump` the users/admin table (use "
        "`--level 3 --risk 2` if id=1 isn't flagged). Pull hashes, API keys, tokens; harvest any credential into "
        "artifacts.tokens and reuse it.\n"
        "- LFI/path-traversal: read the app's OWN source/config (index.php, config.php, .env; php://filter for "
        "source) to recover queries/creds/routes, then act on them.\n"
        "- exposed .git/source: git-extract the tree and scan-secrets it.\n"
        "Quote extracted rows/secret patterns (redacted) as evidence; never fabricate output.")

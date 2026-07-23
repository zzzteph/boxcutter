"""Registry of all tool modules: the ordered list and a name -> module map.

Kept separate from the CLI so both the dispatcher and the YAML workflow runner
can resolve a tool by its NAME without importing each other.
"""

from __future__ import annotations

# Agentic (LLM-driven) commands live in their own package to keep them separate from the deterministic tools.
from ..ai import (
    bob,
    caleb,
    crawlio,
    irvin,
    juicy,
    logio,
    prawlio,
    travis,
)
from . import (
    browser_actions,
    browser_crawl,
    browser_login,
    visual_driver,
    dirb,
    dirsearch,
    dnsx,
    fuzz,
    git_extract,
    graphql_audit,
    graphql_detect,
    http_request,
    httpx_probe,
    js_endpoints,
    katana_crawl,
    nuclei,
    path_bust,
    path_fuzz,
    scan_secrets,
    screenshot,
    sqlmap,
    subfinder,
    swagger_endpoints,
    swagger_parser,
    swagger_specs,
    wayback,
    wayback_domains,
    zap_crawl,
    zap_scan_full,
    zap_scan_openapi,
    zap_scan_url,
)

# Ordered by workflow stage so `--help` reads like a recon->exploit pipeline.
TOOLS = [
    # Recon
    subfinder,
    dnsx,
    httpx_probe,
    screenshot,
    wayback,
    wayback_domains,
    # Crawl
    katana_crawl,
    zap_crawl,
    js_endpoints,
    browser_crawl,
    browser_login,
    browser_actions,
    visual_driver,
    # Vuln scanners
    nuclei,
    sqlmap,
    dirb,
    dirsearch,
    zap_scan_url,
    zap_scan_full,
    zap_scan_openapi,
    # Fuzzing
    path_fuzz,
    path_bust,
    fuzz,
    # Secrets / source
    scan_secrets,
    git_extract,
    # API specs
    swagger_parser,
    swagger_endpoints,
    swagger_specs,
    # GraphQL
    graphql_detect,
    graphql_audit,
    # Generic
    http_request,
]

# Agentic (LLM-driven) commands - grouped under `boxcutter ai <name>`. They need a provider/API key and make
# many LLM calls, so they are their own category. Each is ALSO callable bare (`boxcutter logio`) when no tool
# shares the name; on a name clash a TOOL wins the bare form and `boxcutter ai <name>` forces the agent.
AI = [
    # The full autonomous pipeline (suggester council -> concluder -> planner -> executors -> reporter).
    irvin,
    # Standalone agentic login tool (auth-only agent; completely separate from IRVIN).
    logio,
    # Authenticated crawl: logio logs in, then a visual agent crawls the app for its post-login requests.
    prawlio,
    # Single-agent crawler: comprehensive, VERIFIED endpoint list (strict about false/ghost paths), path-scoped.
    crawlio,
    # Single-agent JS analyst: download a JS file, extract every hidden URL, and find DOM XSS with examples.
    juicy,
    # Short surface scanner: cheap single-pass recon + scanners + light logic checks; exposure-focused report.
    bob,
    # Recon triage scout: probes ONE host lightly and rates how interesting it is for a deeper scan (for bob).
    travis,
    # Multi-phase / multi-identity orchestrator: authed deep scan, reauth, two-account BFLA, multi-step chains.
    caleb,
]

# Every command resolvable by NAME (tools + ai) - toolschema and the workflow runner look themselves up here.
BY_NAME = {module.NAME: module for module in TOOLS + AI}

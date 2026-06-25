"""Registry of all tool modules: the ordered list and a name -> module map.

Kept separate from the CLI so both the dispatcher and the YAML workflow runner
can resolve a tool by its NAME without importing each other.
"""

from __future__ import annotations

from . import (
    bob,
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
    # Agentic (LLM-driven multi-agent bug-hunter over the tools above)
    bob,
]

BY_NAME = {module.NAME: module for module in TOOLS}

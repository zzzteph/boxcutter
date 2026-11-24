"""Registry of all tool modules: the ordered list and a name -> module map.

Kept separate from the CLI so both the dispatcher and the YAML workflow runner
can resolve a tool by its NAME without importing each other. Only the tools the
bundled workflows actually use ship here.
"""

from __future__ import annotations

from . import (
    dns_brute,
    dnsx,
    fuzz,
    graphql_audit,
    graphql_detect,
    harvest,
    httpx_probe,
    js_endpoints,
    katana_crawl,
    nuclei,
    ping_scan,
    scan_secrets,
    sqlmap,
    subfinder,
    swagger_endpoints,
    swagger_specs,
    wayback,
    wayback_domains,
)

# Ordered by workflow stage so `--help` reads like a recon->exploit pipeline.
TOOLS = [
    # Recon
    subfinder,
    dnsx,
    dns_brute,
    ping_scan,
    httpx_probe,
    wayback,
    wayback_domains,
    # Crawl
    katana_crawl,
    harvest,
    js_endpoints,
    # Vuln scanners
    nuclei,
    sqlmap,
    fuzz,
    # Secrets
    scan_secrets,
    # API specs
    swagger_specs,
    swagger_endpoints,
    # GraphQL
    graphql_detect,
    graphql_audit,
]

# Every tool resolvable by NAME - the workflow runner looks itself up here.
BY_NAME = {module.NAME: module for module in TOOLS}

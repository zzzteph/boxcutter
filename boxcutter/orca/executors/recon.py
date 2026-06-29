"""recon/crawler executor - an agent that maps the FULL attack surface into state."""

from __future__ import annotations

from .base import Executor


class Recon(Executor):
    name = "recon"
    description = "Map the attack surface: liveness, OpenAPI spec, crawl, dir brute, JS endpoints."
    tools = {"httpx", "http-request", "katana-crawl", "js-endpoints", "dirsearch", "dirb",
             "swagger-specs", "swagger-parser", "swagger-endpoints", "graphql-detect"}
    max_steps = 16
    objective = (
        "You are the CRAWLER/RECON agent. Build the COMPLETE attack surface and return every endpoint in "
        "artifacts.endpoints - later agents test exactly what you map, so be exhaustive, don't sample.\n"
        "- probe liveness (httpx) and fetch the base.\n"
        "- if an OpenAPI/Swagger spec exists (try /openapi.json and swagger-specs), list ALL its endpoints with "
        "`swagger-endpoints <spec> --fuzzable` - this is usually the whole API.\n"
        "- crawl with katana (--params and --js); pull API paths from each JS file (js-endpoints).\n"
        "- brute dirs with BOTH dirsearch AND dirb (their wordlists differ); recurse into admin/api/.git/upload.\n"
        "- detect GraphQL.\n"
        "Do NOT test for vulns here - just map. Put EVERY endpoint + any spec/graphql/admin URL in "
        "artifacts.endpoints and a count in notes.")

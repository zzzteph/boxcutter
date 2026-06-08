"""wayback - pull historical URLs from public archives. Port of app:wayback.

Queries Wayback Machine, Common Crawl, AlienVault OTX and URLScan sequentially;
a provider failing is logged but never aborts the run (partial results stand).
Large CDX pages are streamed to disk and parsed line-by-line.
"""

from __future__ import annotations

import json

from ..core import fsutil, http
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.urlfilter import is_js_url, param_signature
from urllib.parse import urlparse, urlencode

NAME = "wayback"
KIND = "urls"
HELP = "Pull historical URLs for a domain from 4 public archives (deduped)."


def add_arguments(parser) -> None:
    parser.add_argument("domain", help="Domain to query, e.g. example.com")
    parser.add_argument("--timeout", type=int, default=120, help="Per-provider HTTP timeout in seconds")
    parser.add_argument("--inc-subdomains", "--inc_subdomains", dest="inc_subdomains",
                        action="store_true", help="Include URLs from subdomains")
    parser.add_argument("--js", action="store_true", help="Keep only .js URLs")
    parser.add_argument("--params", action="store_true",
                        help="Keep only URLs with params (dedup by unique param-name set)")
    add_common_args(parser)


def run(args) -> int:
    domain = args.domain.strip().lower()
    timeout = max(5, args.timeout)
    dbg = debug_logger(args.debug)

    if not domain:
        output_result([], args.output, "Empty domain.")
        return 1
    if args.js and args.params:
        output_result([], args.output, "Use either --js or --params, not both.")
        return 1

    providers = {
        "wayback": lambda: _fetch_wayback(domain, timeout, dbg),
        "commoncrawl": lambda: _fetch_commoncrawl(domain, timeout, dbg),
        "otx": lambda: _fetch_otx(domain, timeout, dbg),
        "urlscan": lambda: _fetch_urlscan(domain, timeout, dbg),
    }

    seen: dict[str, bool] = {}
    for name, fn in providers.items():
        dbg(f"-> {name}: querying...")
        try:
            found = fn()
        except Exception as exc:  # noqa: BLE001 - provider isolation is intentional
            dbg(f"<- {name} threw: {exc}")
            continue
        added = in_scope = 0
        for url in found:
            if not isinstance(url, str) or not url or not _matches_scope(url, domain, args.inc_subdomains):
                continue
            in_scope += 1
            if url not in seen:
                seen[url] = True
                added += 1
        dbg(f"{name}: {len(found)} raw, {in_scope} in-scope, {added} new")

    urls = list(seen.keys())

    if args.js:
        urls = [u for u in urls if is_js_url(u)]
    elif args.params:
        by_sig: dict[str, str] = {}
        for u in urls:
            sig = param_signature(u)
            if sig is None or sig in by_sig:
                continue
            by_sig[sig] = u
        urls = list(by_sig.values())

    urls.sort()
    dbg(f"Total unique URLs: {len(urls)}")
    output_result(urls, args.output)
    return 0


def _matches_scope(url: str, domain: str, inc_subdomains: bool) -> bool:
    host = urlparse(url).hostname
    if not host:
        return False
    host = host.lower()
    if host == domain:
        return True
    return inc_subdomains and host.endswith("." + domain)


def _fetch_wayback(domain: str, timeout: int, dbg) -> list[str]:
    urls: list[str] = []
    resume_key: str | None = None
    max_pages, limit, max_urls = 10, 5000, 50000

    for page in range(1, max_pages + 1):
        params = {
            "url": f"*.{domain}/*",
            "fl": "original",
            "collapse": "urlkey",
            "limit": limit,
            "showResumeKey": "true",
        }
        if resume_key is not None:
            params["resumeKey"] = resume_key
        url = "https://web.archive.org/cdx/search/cdx?" + urlencode(params)
        sink = fsutil.temp_file("wayback_cdx_")
        try:
            response = http.download(url, sink, timeout=timeout)
            if not http.is_successful(response):
                fsutil.remove(sink)
                break

            new_resume_key: str | None = None
            blank_seen = False
            with open(sink, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\r\n")
                    if line == "":
                        blank_seen = True
                        continue
                    if blank_seen:
                        new_resume_key = line
                        continue
                    urls.append(line)
        finally:
            fsutil.remove(sink)

        if len(urls) >= max_urls:
            break
        if not new_resume_key:
            break
        resume_key = new_resume_key

    return urls


def _fetch_commoncrawl(domain: str, timeout: int, dbg) -> list[str]:
    resp = http.get("https://index.commoncrawl.org/collinfo.json", timeout=timeout)
    indices = resp.json() if http.is_successful(resp) else None
    if not isinstance(indices, list) or not indices:
        return []
    cdx_api = indices[0].get("cdx-api")
    if not isinstance(cdx_api, str) or not cdx_api:
        return []

    page_size, max_pages, max_urls = 5, 10, 50000

    num_resp = http.get(
        f"{cdx_api}?url=*.{domain}&output=json&showNumPages=true&pageSize={page_size}",
        timeout=timeout,
    )
    if not http.is_successful(num_resp):
        return []
    try:
        num_pages = int(num_resp.text.strip())
    except ValueError:
        return []
    if num_pages <= 0:
        return []
    num_pages = min(num_pages, max_pages)

    urls: list[str] = []
    for page in range(num_pages):
        page_url = f"{cdx_api}?url=*.{domain}&output=json&page={page}&pageSize={page_size}"
        sink = fsutil.temp_file("cc_cdx_")
        try:
            response = http.download(page_url, sink, timeout=timeout)
            if not http.is_successful(response):
                fsutil.remove(sink)
                break
            with open(sink, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(row, dict) and row.get("url"):
                        urls.append(row["url"])
        finally:
            fsutil.remove(sink)
        if len(urls) >= max_urls:
            break
    return urls


def _fetch_otx(domain: str, timeout: int, dbg) -> list[str]:
    urls: list[str] = []
    for page in range(1, 11):
        api = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page={page}"
        response = http.get(api, timeout=timeout)
        if not http.is_successful(response):
            break
        data = response.json()
        if not isinstance(data, dict) or not data.get("url_list"):
            break
        for row in data["url_list"]:
            if row.get("url"):
                urls.append(row["url"])
        if not data.get("has_next"):
            break
    return urls


def _fetch_urlscan(domain: str, timeout: int, dbg) -> list[str]:
    api = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
    response = http.get(api, timeout=timeout)
    if not http.is_successful(response):
        return []
    data = response.json()
    if not isinstance(data, dict) or not data.get("results"):
        return []
    urls: list[str] = []
    for row in data["results"]:
        url = (row.get("task") or {}).get("url") or (row.get("page") or {}).get("url")
        if isinstance(url, str) and url:
            urls.append(url)
    return urls

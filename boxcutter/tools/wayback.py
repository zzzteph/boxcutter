"""wayback - pull historical URLs from public archives. Port of app:wayback.

Queries Wayback Machine, Common Crawl (several recent indexes), AlienVault OTX and
URLScan sequentially; a provider failing is logged but never aborts the run (partial
results stand). Large CDX pages are streamed to disk and parsed line-by-line. Dead and
redirect captures are dropped at the Wayback CDX source, and static-asset/vendor URLs
(.css/.png/.woff, /wp-content, node_modules, ...) are filtered out by default (`--all` keeps them).
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

# Static assets / vendor noise dropped by default (disable with --all). Ported from
# waymore's DEFAULT_FILTER_URL — extensions and path fragments rarely worth testing.
_NOISE_EXT = (
    ".css", ".scss", ".jpg", ".jpeg", ".png", ".svg", ".gif", ".ico", ".bmp", ".tif",
    ".tiff", ".webp", ".avif", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".htc",
    ".mp4", ".mp3", ".m4a", ".m4p", ".mov", ".webm", ".flv", ".ogv", ".wmv", ".wma",
    ".asx", ".swf", ".rtf",
)
_NOISE_PATH = (
    "/wp-content/", "/wp-includes/", "/wp-json/", "/node_modules/", "/jquery",
    "/bootstrap", "/theme", "/themes/", "/fonts/", "/font/", "/css/", "/img/",
    "/images/", "/captcha", "/_incapsula_resource",
)


def _is_noise(url: str) -> bool:
    """True for a static-asset/vendor URL not worth testing (extension or path match)."""
    path = urlparse(url).path.lower()
    return path.endswith(_NOISE_EXT) or any(frag in path for frag in _NOISE_PATH)


def add_arguments(parser) -> None:
    parser.add_argument("domain", help="Domain to query, e.g. example.com")
    parser.add_argument("--timeout", type=int, default=120, help="Per-provider HTTP timeout in seconds")
    parser.add_argument("--inc-subdomains", "--inc_subdomains", dest="inc_subdomains",
                        action="store_true", help="Include URLs from subdomains")
    parser.add_argument("--js", action="store_true", help="Keep only .js URLs")
    parser.add_argument("--params", action="store_true",
                        help="Keep only URLs with params (dedup by unique param-name set)")
    parser.add_argument("--all", dest="include_all", action="store_true",
                        help="Keep static-asset/vendor URLs that are filtered out by default")
    parser.add_argument("--cc-indexes", dest="cc_indexes", type=int, default=3, metavar="N",
                        help="How many recent Common Crawl indexes to query (default 3; 0 = all)")
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
        "commoncrawl": lambda: _fetch_commoncrawl(domain, timeout, dbg, args.cc_indexes),
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

    if not args.include_all:
        before = len(urls)
        urls = [u for u in urls if not _is_noise(u)]
        dbg(f"noise filter: dropped {before - len(urls)} static/vendor URLs (--all to keep)")

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
        params = [
            ("url", f"*.{domain}/*"),
            ("fl", "original"),
            ("collapse", "urlkey"),
            ("limit", limit),
            ("showResumeKey", "true"),
            ("filter", "!statuscode:(404|30[0-9])"),  # drop dead + redirect captures
            ("filter", "!mimetype:warc/revisit"),     # drop duplicate revisit records
        ]
        if resume_key is not None:
            params.append(("resumeKey", resume_key))
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


def _fetch_commoncrawl(domain: str, timeout: int, dbg, max_indexes: int = 3) -> list[str]:
    resp = http.get("https://index.commoncrawl.org/collinfo.json", timeout=timeout)
    indices = resp.json() if http.is_successful(resp) else None
    if not isinstance(indices, list) or not indices:
        return []

    # collinfo.json lists newest first; query the most recent `max_indexes` (0 = all)
    # — a URL may only exist in an older crawl, so sweeping several boosts coverage.
    page_size, max_pages, max_urls = 5, 3, 50000
    if max_indexes <= 0:
        max_indexes = len(indices)

    urls: list[str] = []
    for index in indices[:max_indexes]:
        cdx_api = index.get("cdx-api") if isinstance(index, dict) else None
        if not isinstance(cdx_api, str) or not cdx_api:
            continue

        num_resp = http.get(
            f"{cdx_api}?url=*.{domain}&output=json&showNumPages=true&pageSize={page_size}",
            timeout=timeout,
        )
        if not http.is_successful(num_resp):
            continue
        try:
            num_pages = min(int(num_resp.text.strip()), max_pages)
        except ValueError:
            continue
        if num_pages <= 0:
            continue
        dbg(f"  commoncrawl {index.get('id', cdx_api)}: {num_pages} page(s)")

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
                return urls
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

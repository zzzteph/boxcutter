"""path-fuzz - brute-force a FUZZ position in a URL with the built-in wordlist.
Port of app:path-fuzz."""

from __future__ import annotations

import time

from ..core import http
from ..core.args import add_common_args
from ..core.envelope import debug_logger, output_result
from ..core.rand import random_string
from ..core.validators import is_valid_url
from ..data.path_wordlist import WORDS

NAME = "path-fuzz"
KIND = "findings"
HELP = "Brute-force a FUZZ position in a URL using the built-in path wordlist."

_INTERESTING = {200, 201, 204, 301, 302, 307, 308, 401, 403}


def add_arguments(parser) -> None:
    parser.add_argument("target", help="URL template with FUZZ marker, e.g. https://x/api/FUZZ")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Extra header (repeatable)")
    parser.add_argument("--timeout", type=int, default=300, help="Max total seconds")
    add_common_args(parser)


def run(args) -> int:
    template = args.target.strip()
    method = args.method.strip().upper()
    timeout = args.timeout
    dbg = debug_logger(args.debug)

    custom_headers = _parse_headers(args.header)

    if "FUZZ" not in template:
        output_result([], args.output, "URL template must contain a FUZZ marker.")
        return 1

    base_url = template.replace("FUZZ", "")
    if not is_valid_url(base_url):
        output_result([], args.output, "Invalid URL template.")
        return 1

    dbg(f"Words: {len(WORDS)}")
    dbg(f"Template: {template}")
    dbg(f"Method:   {method}")

    baselines = _baselines(template, method, custom_headers)
    for i, b in enumerate(baselines):
        dbg(f"Baseline {i}: HTTP {b['code']} / {b['size']} bytes")

    findings: list[dict] = []
    started_at = time.time()
    headers = {"User-Agent": "Mozilla/5.0", **custom_headers}

    for word in WORDS:
        if time.time() - started_at >= timeout:
            dbg("Timeout reached, stopping.")
            break

        url = template.replace("FUZZ", word)
        try:
            response = http.request(method, url, headers=headers, timeout=8, verify=False)
        except Exception:  # noqa: BLE001
            continue

        code = response.status_code
        size = len(response.content)
        if _is_baseline(code, size, baselines):
            continue

        dbg(f"  [{code}] {url} ({size}b)")
        findings.append(
            {
                "severity": "info",
                "title": f"path: {url}",
                "info": f"HTTP {code}, {size} bytes (word: {word})",
                "url": url,
            }
        )

    dbg(f"Found {len(findings)} result(s).")
    output_result(findings, args.output)
    return 0


def _baselines(template: str, method: str, custom_headers: dict[str, str]) -> list[dict]:
    probes = [
        "__baseline_" + random_string(20),
        "xxnotreal_" + random_string(15) + ".bak",
        "___nonexistent_" + random_string(18) + "___",
    ]
    headers = {"User-Agent": "Mozilla/5.0", **custom_headers}
    samples: list[dict] = []
    for probe in probes:
        url = template.replace("FUZZ", probe)
        try:
            response = http.request(method, url, headers=headers, timeout=8, verify=False)
        except Exception:  # noqa: BLE001
            continue
        samples.append({"code": response.status_code, "size": len(response.content)})
    return samples


def _is_baseline(code: int, size: int, baselines: list[dict]) -> bool:
    if code not in _INTERESTING:
        return True

    same_status = [b for b in baselines if b["code"] == code]
    if len(same_status) >= 2:
        sizes = sorted(b["size"] for b in same_status)
        median = sizes[len(sizes) // 2]
        if median > 0 and abs(size - median) / median < 0.10:
            return True
        if median == 0 and size == 0:
            return True
    return False


def _parse_headers(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in raw_headers or []:
        if ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        if name.strip():
            headers[name.strip()] = value.strip()
    return headers

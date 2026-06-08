"""Thin HTTP helpers - the Python port of Laravel's ``Http`` facade usage.

The PHP commands lean on a handful of Guzzle behaviours: TLS verification off
(``withoutVerifying``), per-request timeouts, a fixed-delay retry, custom
headers, and streaming a response body to disk (``sink``). These wrappers give
the tool modules the same primitives on top of ``requests``.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Matches the desktop-Chrome UA the PHP fuzzer sends.
CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def session(extra_headers: dict[str, str] | None = None) -> requests.Session:
    """A reusable session (connection pooling) with TLS verification off and the
    Chrome UA preset. Fuzzers fire hundreds of requests at one host, so reusing
    the connection is a real win over a fresh request each time."""
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = CHROME_UA
    if extra_headers:
        sess.headers.update(extra_headers)
    return sess


def send(
    method: str,
    url: str,
    *,
    sess: Optional[requests.Session] = None,
    headers: dict[str, str] | None = None,
    data: Any = None,
    json: Any = None,
    params: dict[str, Any] | None = None,
    timeout: int = 15,
    allow_redirects: bool = True,
) -> dict[str, Any]:
    """Issue one request and return a normalized dict that never raises.

    Unlike :func:`request` (which returns a ``requests.Response`` and propagates
    transport errors), this captures everything the scanners need - decoded body,
    true byte length, timing, final URL - and turns a transport failure into an
    ``error`` string. The shape is::

        {status, headers, body, body_bytes, final_url, time_ms, error}

    ``status`` is ``None`` and ``error`` is set when the request never completed.
    """
    s = sess or session()
    start = time.time()
    try:
        response = s.request(
            method.upper(), url, headers=headers, data=data, json=json,
            params=params, timeout=timeout, allow_redirects=allow_redirects,
        )
        body = response.content
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": body.decode("utf-8", errors="replace"),
            "body_bytes": len(body),
            "final_url": response.url,
            "time_ms": int((time.time() - start) * 1000),
            "error": None,
        }
    except requests.RequestException as exc:
        return {
            "status": None,
            "headers": {},
            "body": "",
            "body_bytes": 0,
            "final_url": url,
            "time_ms": int((time.time() - start) * 1000),
            "error": str(exc),
        }


def request(
    method: str,
    url: str,
    *,
    timeout: int = 30,
    headers: dict[str, str] | None = None,
    data: Any = None,
    json: Any = None,
    params: dict[str, Any] | None = None,
    verify: bool = False,
    allow_redirects: bool = True,
    stream: bool = False,
) -> requests.Response:
    """Issue a single HTTP request. TLS verification is off by default to match
    ``withoutVerifying()`` - these tools routinely hit self-signed targets."""
    return requests.request(
        method.upper(),
        url,
        timeout=timeout,
        headers=headers,
        data=data,
        json=json,
        params=params,
        verify=verify,
        allow_redirects=allow_redirects,
        stream=stream,
    )


def get(url: str, **kwargs: Any) -> requests.Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs: Any) -> requests.Response:
    return request("POST", url, **kwargs)


def with_retries(
    fn: Callable[[], requests.Response],
    retries: int,
    sleep_ms: int,
) -> requests.Response:
    """Run ``fn`` retrying on connection-level failures, fixed ``sleep_ms``
    delay between attempts - mirrors Laravel ``Http::retry($n, $ms)`` which
    only retries thrown transport errors, not 4xx/5xx responses."""
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return fn()
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(sleep_ms / 1000.0)
    assert last_exc is not None
    raise last_exc


def is_successful(response: requests.Response) -> bool:
    """True for 2xx, matching Guzzle/Laravel ``$response->successful()``."""
    return 200 <= response.status_code < 300


def download(url: str, sink_path: str, *, timeout: int = 30, verify: bool = False,
             headers: dict[str, str] | None = None) -> requests.Response:
    """Stream a response body to ``sink_path`` - the port of ``Http::sink()``.

    Used by the archive providers which can return multi-megabyte pages that we
    never want fully resident in memory.
    """
    response = requests.get(
        url, timeout=timeout, verify=verify, headers=headers, stream=True
    )
    with open(sink_path, "wb") as fh:
        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                fh.write(chunk)
    return response

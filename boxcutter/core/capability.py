"""Which tools can actually run in this image.

A tool that wraps an external binary only works if that binary is present. The
same boxcutter code ships in both the full and slim images, so the CLI checks at
runtime which tools are usable: ``--list`` hides the rest, and running one (or a
workflow step that needs one) fails honestly instead of faking an empty result.

Tools not listed here are pure-Python and always available.
"""

from __future__ import annotations

import os
import shutil

# tool NAME -> requirement: a binary on PATH, or an absolute path to a script.
REQUIREMENTS: dict[str, str] = {
    "subfinder": "subfinder",
    "dnsx": "dnsx",
    "httpx": "httpx",
    "screenshot": "chromium-browser",
    "katana-crawl": "katana",
    "nuclei": "nuclei",
    "sqlmap": "/usr/share/sqlmap/sqlmap.py",
    "dirb": "dirb",
    "dirsearch": "/usr/share/dirsearch/dirsearch.py",
    "zap-crawl": "zap.sh",
    "zap-scan-url": "zap.sh",
    "zap-scan-full": "zap.sh",
    "zap-scan-openapi": "zap.sh",
    "browser-crawl": "chromium-browser",
    "browser-login": "chromium-browser",
    "browser-actions": "chromium-browser",
}


def requirement_for(name: str) -> str | None:
    """The external requirement for tool ``name`` (None if pure-Python)."""
    return REQUIREMENTS.get(name)


def available(requirement: str | None) -> bool:
    if not requirement:
        return True
    if requirement.startswith("py:"):          # a Python module (e.g. py:playwright)
        import importlib.util
        return importlib.util.find_spec(requirement[3:]) is not None
    if os.path.isabs(requirement):
        return os.path.exists(requirement)
    return shutil.which(requirement) is not None


def name_available(name: str) -> bool:
    """True when tool ``name``'s requirement is satisfied in this image."""
    return available(REQUIREMENTS.get(name))

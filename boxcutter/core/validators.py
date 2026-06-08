"""Validation helpers - ports of the PHP ``filter_var`` / regex checks.

Kept deliberately permissive in the same places the PHP was permissive, so the
tools accept and reject the same inputs.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# Subfinder's three-part domain check, ported verbatim.
_DOMAIN_LABELS = re.compile(r"^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$", re.I)
_DOMAIN_LENGTH = re.compile(r"^.{1,253}$")
_DOMAIN_PARTS = re.compile(r"^[^\.]{1,63}(\.[^\.]{1,63})*$")


def is_valid_url(value: str | None) -> bool:
    """Approximates ``filter_var($v, FILTER_VALIDATE_URL)``: a scheme and a host
    are required."""
    if not value:
        return False
    try:
        parts = urlparse(value)
    except ValueError:
        return False
    return bool(parts.scheme) and bool(parts.netloc)


def is_valid_domain_name(domain: str) -> bool:
    """Port of Subfinder::isValidDomainName - RFC-ish hostname validation."""
    return bool(
        _DOMAIN_LABELS.match(domain)
        and _DOMAIN_LENGTH.match(domain)
        and _DOMAIN_PARTS.match(domain)
    )


def is_public_ip(ip: str) -> bool:
    """True when ``ip`` is a routable public address.

    Equivalent to ``filter_var($ip, FILTER_VALIDATE_IP,
    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)`` - rejects private,
    loopback, link-local, reserved, multicast and unspecified ranges.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def has_public_ip(ips: list[str]) -> bool:
    return any(is_public_ip(ip) for ip in ips if ip)

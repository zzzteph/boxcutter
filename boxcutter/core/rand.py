"""Random-string helper matching Laravel's ``Str::random`` alphabet."""

from __future__ import annotations

import secrets
import string

_ALPHABET = string.ascii_letters + string.digits


def random_string(length: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))

"""Temp-file/dir helpers - ports of ``tempnam`` / ``sys_get_temp_dir`` usage."""

from __future__ import annotations

import os
import shutil
import tempfile


def temp_file(prefix: str) -> str:
    """Create an empty temp file and return its path (like PHP ``tempnam``)."""
    fd, path = tempfile.mkstemp(prefix=prefix)
    os.close(fd)
    return path


def temp_dir(prefix: str) -> str:
    """Create a temp directory and return its path."""
    return tempfile.mkdtemp(prefix=prefix)


def read_text(path: str) -> str:
    """Read a file's contents, returning '' if it does not exist."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def read_bytes(path: str) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def remove(path: str) -> None:
    """Best-effort unlink - never raises."""
    try:
        os.unlink(path)
    except OSError:
        pass


def remove_dir(path: str) -> None:
    """Best-effort recursive directory removal - never raises."""
    shutil.rmtree(path, ignore_errors=True)

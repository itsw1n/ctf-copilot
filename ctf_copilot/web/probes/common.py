"""Deprecated shim (Phase 9, Task 15). Use WebSession + differential instead.

Kept for import compatibility only; no active probe imports this module.
"""
from __future__ import annotations

from typing import Any

from ..session import WebSession
from .. import differential as diff

UA = "CTF-Copilot/1.0 authorized-security-test"


def request(url: str, method: str = "GET", timeout: float = 8):
    """Compat helper delegating to WebSession (GET/HEAD/OPTIONS only)."""
    sess = WebSession(base_url=url, timeout=timeout)
    upper = (method or "GET").upper()
    if upper == "GET":
        r = sess.get(url)
    elif upper == "HEAD":
        r = sess.head(url)
    elif upper == "OPTIONS":
        r = sess.options(url)
    else:
        raise ValueError(f"unsafe method blocked: {method!r}")
    return r.status, dict(r.headers), r.text

"""Thin compat wrapper over WebSession (Phase 9, Task 15).

Legacy ``fetch(url)`` kept for backward compatibility; all active code paths
use :class:`ctf_copilot.web.session.WebSession` directly. No network paths here
beyond delegating to WebSession (same-origin, ledger, caps).
"""
from __future__ import annotations

from typing import Any

from .session import USER_AGENT, WebSession

__all__ = ["USER_AGENT", "fetch"]


def fetch(url: str, headers: Any = None, cookies: Any = None,
          timeout: float = 10, max_bytes: int = 2_000_000):
    """Fetch ``url`` via WebSession; return legacy tuple.

    Returns ``(status, final_url, headers, body, cookie_jar)`` to match the
    historic ``web/client.py`` contract. Prefer ``WebSession`` for new code.
    """
    sess = WebSession(base_url=url, headers=headers, cookies=cookies,
                      timeout=timeout, max_bytes=max_bytes)
    resp = sess.get(url)
    try:
        jar = sess.session.cookies
    except Exception:
        jar = None
    return resp.status, resp.final_url, dict(resp.headers), resp.text, jar

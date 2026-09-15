"""Safe-method probe via WebSession (Phase 9, Task 15).

Only GET/HEAD/OPTIONS are exercised. No state-changing methods, no PUT/DELETE,
no POST auto-submit. Same-origin + budget enforced by WebSession.
"""
from __future__ import annotations

from typing import Any

from ..session import WebSession


def probe(url: str, session: Any | None = None, max_requests: int = 6) -> list[str]:
    if session is None:
        session = WebSession(base_url=url, max_requests=max_requests)
    if not session.can_fetch(url):
        raise ValueError(f"blocked cross-origin request: {url!r} (base {session.base_url})")
    start = len(session.ledger)

    def _guard():
        if (len(session.ledger) - start) >= max_requests:
            raise RuntimeError(f"request budget exhausted ({max_requests} max for technique)")

    out: list[str] = []
    for method in ("GET", "HEAD", "OPTIONS"):
        _guard()
        try:
            if method == "GET":
                resp = session.get(url)
            elif method == "HEAD":
                resp = session.head(url)
            else:
                resp = session.options(url)
            allow = ""
            try:
                low = {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
                allow = low.get("allow", "")
            except Exception:
                allow = ""
            extra = f" allow={allow}" if allow else ""
            out.append(f"{method:<7} {resp.status}{extra}")
        except (ValueError, RuntimeError):
            raise
        except Exception as exc:
            out.append(f"{method:<7} error: {exc.__class__.__name__}")
    out.append("note: only safe methods tested; verify Allow header manually with curl -i -X OPTIONS URL.")
    return out

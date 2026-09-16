"""Safe-method probe via WebSession (Phase 9, Task 15).

Only GET/HEAD/OPTIONS are exercised. No state-changing methods, no PUT/DELETE,
no POST auto-submit. Same-origin + budget enforced by WebSession.
"""
from __future__ import annotations

from typing import Any

from ..session import WebSession
from .. import differential as diff


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
    _guard()
    try:
        base = diff.fetch_bounded(session, "GET", url)
    except (ValueError, RuntimeError):
        raise
    except Exception as exc:
        base = None  # type: ignore[assignment]
        out.append(f"{'GET':<7} error: {exc.__class__.__name__}")
    if base is not None:
        try:
            allow0 = (base.headers or {}).get("allow", "")
        except Exception:
            allow0 = ""
        extra0 = f" allow={allow0}" if allow0 else ""
        out.append(f"{'GET':<7} {base.status}{extra0}")
    for method in ("HEAD", "OPTIONS"):
        _guard()
        try:
            resp = diff.fetch_bounded(session, method, url)
            if base is not None:
                try:
                    _cmp = diff.compare(base, resp)
                except Exception:
                    pass
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

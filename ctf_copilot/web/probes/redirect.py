"""Open-redirect probe (Phase 9, Task 15). GET-only, same-origin, bounded."""
from __future__ import annotations

import urllib.parse
from typing import Any

from ..session import WebSession
from .. import differential as diff

EVIL = "https://evil.example/phish"


def _target_param(url: str) -> str | None:
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not qs:
        return None
    for cand in ("next", "url", "redirect", "return", "dest", "continue", "to"):
        for k, _ in qs:
            if k.lower() == cand:
                return k
    return qs[0][0]


def _replace(url: str, key: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    nq = [(k, value if k == key else v) for k, v in q]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(nq), parts.fragment))


def _host(u: str) -> str:
    try:
        return urllib.parse.urlsplit(u).netloc.lower()
    except Exception:
        return ""


def probe(url: str, session: Any | None = None, max_requests: int = 6) -> list[str]:
    if session is None:
        session = WebSession(base_url=url, max_requests=max_requests)
    if not session.can_fetch(url):
        raise ValueError(f"blocked cross-origin request: {url!r} (base {session.base_url})")
    start = len(session.ledger)

    def _guard():
        if (len(session.ledger) - start) >= max_requests:
            raise RuntimeError(f"request budget exhausted ({max_requests} max for technique)")

    key = _target_param(url)
    if key is None:
        return ["redirect: inconclusive - no query parameter to test (candidate only)."]
    target = _replace(url, key, EVIL)
    _guard()
    try:
        base = diff.fetch_bounded(session, "GET", url)
    except (ValueError, RuntimeError):
        raise
    except Exception as exc:
        return [f"redirect ?{key}=evil: candidate - request error {exc}; not proof."]
    _guard()
    try:
        resp = diff.fetch_bounded(session, "GET", target, allow_redirects=False)
    except (ValueError, RuntimeError):
        raise
    except Exception as exc:
        return [f"redirect ?{key}=evil: candidate - request error {exc}; not proof."]
    try:
        _cmp = diff.compare(base, resp)
    except Exception:
        pass
    loc = ""
    try:
        low = {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
        loc = low.get("location", "")
    except Exception:
        loc = ""
    final = str(getattr(resp, "final_url", "") or "")
    base_host = _host(session.base_url)
    loc_host = _host(loc) if loc else ""
    final_host = _host(final) if final else ""
    evil_host = _host(EVIL)
    if (loc_host == evil_host) or (final_host == evil_host and final_host != base_host):
        return [f"redirect ?{key}=evil: deterministic - cross-host redirect to {loc or final} observed. "
                f"handoff: curl -i {target!r}; verify Location in Burp."]
    if loc and loc_host and loc_host != base_host:
        return [f"redirect ?{key}=evil: deterministic - cross-host redirect to {loc} observed. "
                f"handoff: curl -i {target!r}; verify Location in Burp."]
    return [f"redirect ?{key}=evil: candidate - no cross-host redirect "
            f"(location={loc!r} final={final!r}); not proof. "
            f"handoff: curl -i {target!r} to confirm manually."]

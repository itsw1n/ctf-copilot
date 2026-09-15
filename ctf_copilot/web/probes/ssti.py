"""SSTI arithmetic marker probe (Phase 9, Task 15). GET-only, same-origin, bounded."""
from __future__ import annotations

import urllib.parse
from typing import Any

from ..session import WebSession
from .. import differential as diff

PAYLOAD = "{{7*7}}"
MARKER = "49"


def _target_param(url: str) -> str | None:
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not qs:
        return None
    for cand in ("name", "q", "search", "input", "msg", "template"):
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
        return ["ssti: inconclusive - no query parameter to test (candidate only)."]
    _guard()
    base = diff.fetch_bounded(session, "GET", url)
    _guard()
    variant = diff.fetch_bounded(session, "GET", _replace(url, key, PAYLOAD))
    cmp = diff.compare(base, variant, reflection_marker=MARKER)
    base_has = MARKER in (base.body_text or "")
    var_has = MARKER in (variant.body_text or "")
    if var_has and not base_has:
        return [f"ssti ?{key}={PAYLOAD}: deterministic - arithmetic marker {MARKER!r} rendered "
                f"(similarity {cmp['similarity']:.2f}). "
                f"handoff: curl {variant.url!r}; verify in Burp Repeater before concluding."]
    return [f"ssti ?{key}={PAYLOAD}: candidate - no arithmetic evaluation observed "
            f"(similarity {cmp['similarity']:.2f}); not proof. "
            f"handoff: curl {variant.url!r}; manual review required."]

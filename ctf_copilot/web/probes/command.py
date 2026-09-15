"""Command-injection syntax indicators (Phase 9, Task 15).

GET-only, same-origin, bounded (max 2 payloads). Candidate only: never claims
proof even when shell-output markers appear, to avoid false certainty.
"""
from __future__ import annotations

import urllib.parse
from typing import Any

from ..session import WebSession
from .. import differential as diff

PAYLOADS = ["127.0.0.1;id", "127.0.0.1|id"]
MARKERS = ["uid=", "gid=", "root:x:0:0"]


def _target_param(url: str) -> str | None:
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not qs:
        return None
    for cand in ("ip", "host", "addr", "cmd", "ping", "target"):
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
        return ["cmd: inconclusive - no query parameter to test (candidate only)."]
    _guard()
    base = diff.fetch_bounded(session, "GET", url)
    rows: list[str] = []
    for payload in PAYLOADS[:2]:
        _guard()
        variant = diff.fetch_bounded(session, "GET", _replace(url, key, payload))
        vtext = variant.body_text or ""
        hit = next((m for m in MARKERS if m in vtext), None)
        cmp = diff.compare(base, variant)
        if hit:
            rows.append(
                f"cmd ?{key}={payload}: candidate - shell-output indicator {hit!r} observed "
                f"(status {cmp['status_before']}->{cmp['status_after']}); not proof (candidate only). "
                f"handoff: inspect in Burp Repeater; do not run further commands.")
        else:
            rows.append(
                f"cmd ?{key}={payload}: candidate - no indicator "
                f"(status {cmp['status_before']}->{cmp['status_after']}, similarity {cmp['similarity']:.2f}); not proof.")
    rows.append("handoff: manual Burp review only; no automated exploitation.")
    return rows

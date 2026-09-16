"""Numeric IDOR probe (Phase 9, Task 15). GET-only, same-origin, bounded."""
from __future__ import annotations

import re
import urllib.parse
from typing import Any

from ..session import WebSession
from .. import differential as diff

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Flag detection delegates to shared/flags.py (single source of truth) so
# configured prefixes (e.g. DICT) are honored in IDOR comparison.
from ...shared.flags import find_flags as _find_flags

HANDOFF = (
    "handoff: confirm manually with curl 'URL_A' vs curl 'URL_B'; "
    "then use Burp Repeater changing id=N/N+1; ffuf -u 'URL_FUZZ' -w ids.txt; "
    "gobuster dir -u 'URL_BASE' -w ids.txt"
)


def _base_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except Exception:
        return url


def _numeric_params(url: str) -> list[tuple[str, str]]:
    parts = urllib.parse.urlsplit(url)
    out = []
    for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        try:
            int(v)
            out.append((k, v))
        except Exception:
            continue
    return out


def _replace_param(url: str, key: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    nq = [(k, value if k == key else v) for k, v in q]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(nq), parts.fragment))


def probe(url: str, session: Any | None = None, max_requests: int = 6) -> list[str]:
    """GET /item?id=N vs N+1; deterministic only on email/flag marker change."""
    if session is None:
        session = WebSession(base_url=url, max_requests=max_requests)
    if not session.can_fetch(url):
        raise ValueError(f"blocked cross-origin request: {url!r} (base {session.base_url})")
    start = len(session.ledger)

    def _guard():
        if (len(session.ledger) - start) >= max_requests:
            raise RuntimeError(f"request budget exhausted ({max_requests} max for technique)")

    nums = _numeric_params(url)
    if not nums:
        return ["idor: inconclusive - no numeric id parameter found (candidate only; verify params manually)."]
    key, val = nums[0]
    try:
        nxt = str(int(val) + 1)
    except Exception:
        return ["idor: inconclusive - numeric id not parseable."]
    _guard()
    base = diff.fetch_bounded(session, "GET", url)
    _guard()
    variant = diff.fetch_bounded(session, "GET", _replace_param(url, key, nxt))
    cmp = diff.compare(base, variant)
    base_emails = set(m.lower() for m in EMAIL_RE.findall(base.body_text or ""))
    var_emails = set(m.lower() for m in EMAIL_RE.findall(variant.body_text or ""))
    base_flags = set(m.lower() for m in _find_flags(base.body_text or ""))
    var_flags = set(m.lower() for m in _find_flags(variant.body_text or ""))
    email_changed = bool(var_emails - base_emails)
    flag_changed = bool(var_flags - base_flags)
    summary = (f"status {cmp['status_before']}->{cmp['status_after']}, "
               f"len_delta {cmp['len_delta']}, similarity {cmp['similarity']:.2f}, "
               f"title {cmp['title_before']!r}->{cmp['title_after']!r}")
    if email_changed or flag_changed:
        marker = "flag pattern" if flag_changed else "user email"
        return [f"idor ?{key}={val} vs {nxt}: deterministic - different {marker} observed ({summary}). "
                + HANDOFF.replace("URL_A", url).replace("URL_B", _replace_param(url, key, nxt)).replace(
                    "URL_FUZZ", _replace_param(url, key, "FUZZ")).replace("URL_BASE", _base_url(url))]
    return [f"idor ?{key}={val} vs {nxt}: candidate - response differs or inconclusive ({summary}); "
            f"not proof. Manual review required. "
            + HANDOFF.replace("URL_A", url).replace("URL_B", _replace_param(url, key, nxt)).replace(
                "URL_FUZZ", _replace_param(url, key, "FUZZ")).replace("URL_BASE", _base_url(url))]

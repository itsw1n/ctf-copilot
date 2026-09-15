"""XSS reflection via WebSession + differential (Phase 9, Task 15)."""
from __future__ import annotations

from typing import Any

from ..session import WebSession
from .. import differential as diff

MARKER = "CTFCP_XSS_9f31<svg/onload=alert(1)>"


def _split_query(url: str):
    base, sep, qs = url.partition("?")
    if not sep:
        return base, "", []
    frag = ""
    if "#" in qs:
        qs, _, f = qs.partition("#")
        frag = "#" + f
    pairs = qs.split("&") if qs else []
    parsed: list[tuple[str, str]] = []
    for p in pairs:
        if "=" in p:
            k, _, v = p.partition("=")
            parsed.append((k, v))
        elif p:
            parsed.append((p, ""))
    return base, frag, parsed


def _encode(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalnum() or ch in "-_.~":
            out.append(ch)
        elif ch == " ":
            out.append("%20")
        else:
            out.append("%%%02X" % ord(ch))
    return "".join(out)


def _mutate(url: str, value: str):
    base, frag, pairs = _split_query(url)
    out = []
    for i, (k, _v) in enumerate(pairs):
        nq = [(kk, value if idx == i else vv) for idx, (kk, vv) in enumerate(pairs)]
        qs = "&".join(f"{kk}={_encode(vv)}" for kk, vv in nq)
        out.append((k, f"{base}?{qs}{frag}"))
    return out


def probe(url: str, session: Any | None = None, max_requests: int = 6) -> list[str]:
    if session is None:
        session = WebSession(base_url=url, max_requests=max_requests)
    if not session.can_fetch(url):
        raise ValueError(f"blocked cross-origin request: {url!r} (base {session.base_url})")
    start = len(session.ledger)

    def _guard():
        if (len(session.ledger) - start) >= max_requests:
            raise RuntimeError(f"request budget exhausted ({max_requests} max for technique)")

    muts = _mutate(url, MARKER)[:6]
    if not muts:
        return ["No query parameters found."]
    _guard()
    base = diff.fetch_bounded(session, "GET", url)
    rows: list[str] = []
    for param, variant_url in muts:
        _guard()
        try:
            variant = diff.fetch_bounded(session, "GET", variant_url)
        except (ValueError, RuntimeError):
            raise
        except Exception as exc:
            rows.append(f"{param}: candidate - request error {exc}")
            continue
        cmp = diff.compare(base, variant, reflection_marker=MARKER)
        if cmp.get("reflection"):
            rows.append(f"{param}: candidate - raw marker reflected - inspect context manually "
                        f"(status {variant.status}); not proof. "
                        f"handoff: curl {variant_url!r}; verify in Burp Repeater.")
        else:
            rows.append(f"{param}: candidate - no raw reflection observed (status {variant.status}); not proof.")
    return rows

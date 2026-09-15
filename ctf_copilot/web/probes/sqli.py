"""SQLi indicators via WebSession + differential (Phase 9, Task 15)."""
from __future__ import annotations

from typing import Any

from ..session import WebSession
from .. import differential as diff


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

    muts = _mutate(url, "'")[:6]
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
        cmp = diff.compare(base, variant)
        sig: list[str] = []
        if cmp.get("error_signatures"):
            sig.append("SQL-like error text (%s)" % ",".join(cmp["error_signatures"]))
        if cmp.get("status_changed") and (cmp.get("status_after") or 0) >= 500 > (cmp.get("status_before") or 0):
            sig.append(f"status {cmp['status_before']}->{cmp['status_after']}")
        try:
            body_len = max(1, len(base.body_text or ""))
            if abs(cmp.get("len_delta", 0)) > max(120, int(body_len * 0.2)):
                sig.append("large body-size change")
        except Exception:
            pass
        if sig:
            rows.append(f"{param}: candidate - " + ", ".join(sig) +
                        f" (similarity {cmp['similarity']:.2f}); not proof. "
                        f"handoff: sqlmap -u {variant_url!r} --batch --level 1; confirm manually.")
        else:
            rows.append(f"{param}: candidate - no obvious indicator (similarity {cmp['similarity']:.2f}); not proof.")
    return rows

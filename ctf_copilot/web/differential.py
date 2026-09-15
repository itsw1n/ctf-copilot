"""Bounded differential comparison engine (Phase 7, Task 13).

Generic building block shared by future SQLi/IDOR/method/header/redirect
probes. No live network here beyond delegating to a WebSession; all
comparison is offline. Timing is opt-in only.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# Dynamic noise normalized away before similarity: CSRF-ish hidden values,
# long hex/base64 tokens, ISO dates, nonce="..." attributes.
NORMALIZE_PATTERNS = [
    re.compile(r'(?i)(csrf|xsrf|token|nonce|state|sessionid|session_id|authenticity)[^>="\'<=]{0,20}["\']?\s*[:=]\s*["\']?[^"\'<>\s&;]{4,}["\']?'),
    re.compile(r'value\s*=\s*["\'][0-9a-fA-F]{12,}["\']'),
    re.compile(r'\b[0-9a-fA-F]{16,}\b'),
    re.compile(r'\b[A-Za-z0-9_\-]{20,}={0,2}\b'),  # long base64-ish blobs
    re.compile(r'\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?\b'),
    re.compile(r'(?i)nonce\s*=\s*["\'][^"\']*["\']'),
]
NORMALIZE_TOKEN = "__DYN__"

ERROR_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sql-syntax", re.compile(r"sql syntax", re.I)),
    ("mysql", re.compile(r"mysql", re.I)),
    ("sqlite", re.compile(r"sqlite", re.I)),
    ("postgresql", re.compile(r"postgres", re.I)),
    ("ora-error", re.compile(r"ora-\d+", re.I)),
    ("odbc", re.compile(r"odbc", re.I)),
    ("unterminated-quote", re.compile(r"unterminated (quoted|string)", re.I)),
    ("database-error", re.compile(r"database error", re.I)),
    ("sql-error", re.compile(r"sql[^a-z]{0,12}error", re.I)),
    ("jdbc", re.compile(r"jdbc|sqlexception", re.I)),
]

BODY_TEXT_CAP = 200_000


def normalize_body(text: str) -> str:
    """Strip dynamic noise (CSRF tokens, dates, nonces) for stable similarity."""
    out = text or ""
    for pat in NORMALIZE_PATTERNS:
        out = pat.sub(NORMALIZE_TOKEN, out)
    return out


def extract_title(html: str) -> str:
    m = TITLE_RE.search(html or "")
    return (m.group(1).strip() if m else "")


@dataclass
class BoundedResponse:
    status: int
    url: str
    final_url: str
    headers: dict[str, str] = field(default_factory=dict)
    title: str = ""
    body_text: str = ""
    body_len: int = 0
    ms: float = 0.0
    truncated: bool = False
    history: list[str] = field(default_factory=list)


def _header_subset(headers: Any) -> dict[str, str]:
    try:
        items = dict(headers or {})
    except Exception:
        return {}
    out: dict[str, str] = {}
    for k, v in items.items():
        out[str(k).lower()] = str(v)[:500]
    return out


def fetch_bounded(
    session: Any,
    method: str = "GET",
    url: str = "",
    params: dict[str, Any] | None = None,
    data: Any = None,
    json_data: Any = None,
    extra_headers: dict[str, str] | None = None,
    max_body: int = BODY_TEXT_CAP,
) -> BoundedResponse:
    """Fetch via a WebSession, returning a truncated BoundedResponse.

    Works with WebSession (get/post_form/post_json) or any object exposing
    ``.request``/``.get``. Response bodies are truncated to ``max_body`` chars.
    """
    method = (method or "GET").upper()
    kw: dict[str, Any] = {}
    if extra_headers:
        kw["headers"] = dict(extra_headers)
    resp: Any
    if hasattr(session, "get") and method == "GET":
        resp = session.get(url, params=params, **kw)
    elif hasattr(session, "post_json") and method in ("POST", "PUT", "PATCH") and json_data is not None:
        resp = session.post_json(url, json_data, **kw)
    elif hasattr(session, "post_form") and method in ("POST", "PUT", "PATCH"):
        resp = session.post_form(url, dict(data or {}), csrf_preserve=False, **kw)
    elif hasattr(session, "request"):
        resp = session.request(method, url, **kw)
    else:  # pragma: no cover - defensive
        raise TypeError("session object needs get/post_form/post_json or request")
    # WebSession returns WebResponse; tolerate raw requests responses / mocks.
    status = int(getattr(resp, "status", getattr(resp, "status_code", 0)) or 0)
    req_url = str(getattr(resp, "url", url) or url)
    final_url = str(getattr(resp, "final_url", getattr(resp, "url", url)) or url)
    headers = _header_subset(getattr(resp, "headers", {}))
    text = str(getattr(resp, "text", "") or "")
    truncated = bool(getattr(resp, "truncated", False))
    ms = float(getattr(resp, "ms", getattr(resp, "elapsed_ms", 0.0)) or 0.0)
    history: list[str] = list(getattr(resp, "history", []) or [])
    body_len = int(getattr(resp, "bytes", getattr(resp, "body_len", 0)) or len(text.encode()))
    if len(text) > max_body:
        text = text[:max_body]
        truncated = True
    title = ""
    try:
        title = extract_title(text)
    except Exception:
        pass
    return BoundedResponse(
        status=status, url=req_url, final_url=final_url, headers=headers,
        title=title, body_text=text, body_len=body_len, ms=ms,
        truncated=truncated, history=history,
    )


def compare(
    base: BoundedResponse,
    variant: BoundedResponse,
    include_timing: bool = False,
    keywords: list[str] | None = None,
    reflection_marker: str | None = None,
) -> dict[str, Any]:
    """Compare two bounded responses; offline only.

    Returns dict with: status_changed, status_before/after, len_delta,
    similarity (difflib ratio on normalized bodies), title_changed,
    redirect_changed, header_diffs, error_signatures, keywords_present.
    Timing included only when ``include_timing=True``.
    """
    norm_a = normalize_body(base.body_text or "")
    norm_b = normalize_body(variant.body_text or "")
    similarity = difflib.SequenceMatcher(None, norm_a, norm_b).ratio() if (norm_a or norm_b) else 1.0

    ha = {str(k).lower(): str(v) for k, v in (base.headers or {}).items()}
    hb = {str(k).lower(): str(v) for k, v in (variant.headers or {}).items()}
    header_diffs: dict[str, tuple[str | None, str | None]] = {}
    for key in sorted(set(ha) | set(hb)):
        if ha.get(key) != hb.get(key):
            header_diffs[key] = (ha.get(key), hb.get(key))

    error_signatures: list[str] = []
    vtext = variant.body_text or ""
    for name, pat in ERROR_PATTERNS:
        try:
            if pat.search(vtext):
                # report when variant shows it (indicators, not proof)
                error_signatures.append(name)
        except Exception:
            pass
    keywords_present: list[str] = []
    for kw in keywords or []:
        try:
            if kw and kw in vtext:
                keywords_present.append(kw)
        except Exception:
            pass
    reflection = False
    if reflection_marker:
        reflection = reflection_marker in vtext
        if reflection and reflection_marker not in error_signatures and reflection_marker not in keywords_present:
            keywords_present.append(reflection_marker)

    out: dict[str, Any] = {
        "status_changed": base.status != variant.status,
        "status_before": base.status,
        "status_after": variant.status,
        "len_delta": int(variant.body_len or 0) - int(base.body_len or 0),
        "similarity": float(similarity),
        "title_changed": (base.title or "") != (variant.title or ""),
        "title_before": base.title or "",
        "title_after": variant.title or "",
        "redirect_changed": (base.final_url or "") != (variant.final_url or ""),
        "header_diffs": header_diffs,
        "error_signatures": error_signatures,
        "keywords_present": keywords_present,
        "reflection": reflection,
    }
    if include_timing:
        out["timing_ms"] = {"base": float(base.ms or 0.0), "variant": float(variant.ms or 0.0)}
    return out

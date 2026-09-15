"""Shared web session with ledger, origin policy, and reporting hygiene (Phase 7, Task 13).

Stable interfaces for Tasks 14-16 (passive consolidation, authorized probes, benchmarks).
Backward compatible: legacy ``web/client.py`` functions are untouched.
"""
from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

import requests

USER_AGENT = "CTF-Copilot/1.0"
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}


def parse_header(spec: str) -> tuple[str, str]:
    """Parse ``"Name: value"`` into (name, value)."""
    if ":" not in spec:
        raise ValueError(f"header must look like 'Name: value', got {spec!r}")
    name, _, value = spec.partition(":")
    name, value = name.strip(), value.strip()
    if not name:
        raise ValueError(f"bad header spec {spec!r}")
    return name, value


def parse_cookie(spec: str) -> tuple[str, str]:
    """Parse ``"name=value"`` into (name, value)."""
    if "=" not in spec:
        raise ValueError(f"cookie must look like 'name=value', got {spec!r}")
    name, _, value = spec.partition("=")
    name, value = name.strip(), value.strip()
    if not name:
        raise ValueError(f"bad cookie spec {spec!r}")
    return name, value


def _coerce_headers(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if isinstance(headers, dict):
        return dict(headers)
    out: dict[str, str] = {}
    for item in headers:  # list of "Name: value" or pairs
        if isinstance(item, str):
            k, v = parse_header(item)
            out[k] = v
        else:
            k, v = item
            out[str(k)] = str(v)
    return out


def _coerce_cookies(cookies: Any) -> dict[str, str]:
    if cookies is None:
        return {}
    if isinstance(cookies, dict):
        return {str(k): str(v) for k, v in cookies.items()}
    out: dict[str, str] = {}
    for item in cookies:
        if isinstance(item, str):
            k, v = parse_cookie(item)
            out[k] = v
        else:
            k, v = item
            out[str(k)] = str(v)
    return out


def _redact(value: str) -> str:
    value = str(value)
    if len(value) <= 4:
        return "***"
    # show scheme/prefix only, e.g. "Bearer abc..." -> "Bear***"
    return value[:4] + "***"


class _HiddenInputs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tokens: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        d = {k.lower(): (v or "") for k, v in attrs}
        if d.get("type", "").lower() == "hidden" and d.get("name"):
            self.tokens[d["name"]] = d.get("value", "")


def extract_hidden_tokens(html: str) -> dict[str, str]:
    """Parse hidden <input> tokens from a form page."""
    p = _HiddenInputs()
    try:
        p.feed(html or "")
    except Exception:
        pass
    return dict(p.tokens)


@dataclass
class WebResponse:
    status: int
    status_code: int
    url: str
    final_url: str
    history: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    content: bytes = b""
    truncated: bool = False
    ms: float = 0.0
    bytes: int = 0


class WebSession:
    """Shared requests.Session wrapper with origin policy + ledger.

    - Same-origin enforced via urljoin + netloc check; cross-origin raises ValueError.
    - Cookie persistence via requests.Session cookie jar.
    - Per-request timeout + response-size cap (stream + truncate).
    - Redirect history captured; ledger tracks {method,url,status,bytes,ms}.
    - ``budget`` may be a dict with ``budget["requests"]`` or an object with
      ``.requests``; incremented per recorded request (including CSRF pre-GETs).
    - TLS verification ON by default (``verify=True``); pass explicit
      ``verify=False`` only when the caller opts in.
    """

    def __init__(
        self,
        base_url: str,
        headers: Any = None,
        cookies: Any = None,
        timeout: float = 10,
        max_bytes: int = 2_000_000,
        max_requests: int = 100,
        budget: Any = None,
        verify: bool = True,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            base_url = "http://" + base_url
        parts = urllib.parse.urlsplit(base_url)
        self.base_url = base_url
        self.origin = (parts.scheme, parts.netloc)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_requests = max_requests
        self.budget = budget
        self.verify = verify
        self.ledger: list[dict[str, Any]] = []

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.headers.update(_coerce_headers(headers))
        for k, v in _coerce_cookies(cookies).items():
            self.session.cookies.set(k, v)
        # Never disable TLS globally; per-session verify flag only.
        self.session.verify = verify

    # -- origin policy -------------------------------------------------
    def resolve(self, url: str) -> str:
        return urllib.parse.urljoin(self.base_url, url)

    def can_fetch(self, url: str) -> bool:
        try:
            absu = self.resolve(url)
            parts = urllib.parse.urlsplit(absu)
            if parts.scheme not in ("http", "https"):
                return False
            return (parts.scheme, parts.netloc) == self.origin
        except Exception:
            return False

    def _require_origin(self, url: str) -> str:
        absu = self.resolve(url)
        if not self.can_fetch(absu):
            raise ValueError(f"blocked cross-origin request: {url!r} (base {self.base_url})")
        return absu

    def _require_budget(self) -> None:
        if len(self.ledger) >= self.max_requests:
            raise RuntimeError(f"request budget exhausted ({self.max_requests} max)")

    def _bump_budget(self) -> None:
        try:
            if self.budget is None:
                return
            if isinstance(self.budget, dict):
                self.budget["requests"] = int(self.budget.get("requests", 0)) + 1
            elif hasattr(self.budget, "requests"):
                self.budget.requests = int(getattr(self.budget, "requests") or 0) + 1
        except Exception:
            pass

    def _record(self, method: str, url: str, status: int, nbytes: int, ms: float) -> None:
        self.ledger.append({"method": method, "url": url, "status": status, "bytes": nbytes, "ms": ms})
        self._bump_budget()

    def _read_bounded(self, resp: Any) -> tuple[bytes, bool]:
        """Read up to max_bytes; return (data, truncated). Works with real + mocked responses."""
        chunks: list[bytes] = []
        total = 0
        truncated = False
        # Prefer iter_content when available (real streaming + mocks); else .content.
        try:
            if hasattr(resp, "iter_content"):
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8", "replace")
                    take = self.max_bytes - total
                    if take <= 0:
                        truncated = True
                        break
                    if len(chunk) > take:
                        chunks.append(chunk[:take])
                        total += take
                        truncated = True
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                return b"".join(chunks), truncated
        except Exception:
            if chunks:
                return b"".join(chunks), True
            pass
        raw = getattr(resp, "content", b"") or b""
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "replace")
        if len(raw) > self.max_bytes:
            return raw[: self.max_bytes], True
        return raw, False

    def _wrap(self, method: str, absu: str, resp: Any, data: bytes, truncated: bool, ms: float) -> WebResponse:
        try:
            status = int(getattr(resp, "status_code", 0) or 0)
        except Exception:
            status = 0
        try:
            final = str(getattr(resp, "url", absu) or absu)
        except Exception:
            final = absu
        history: list[str] = []
        try:
            for h in getattr(resp, "history", []) or []:
                u = getattr(h, "url", None) or str(h)
                history.append(str(u))
        except Exception:
            pass
        headers: dict[str, str] = {}
        try:
            headers = {str(k): str(v) for k, v in dict(getattr(resp, "headers", {}) or {}).items()}
        except Exception:
            pass
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            text = ""
        # If body empty but mock provides .text, use it bounded (test-double tolerance)
        if not data and getattr(resp, "text", None):
            try:
                text = str(resp.text)[: self.max_bytes]
                data = text.encode("utf-8", "replace")
                truncated = len(str(resp.text).encode("utf-8", "replace")) > self.max_bytes
            except Exception:
                pass
        wr = WebResponse(
            status=status, status_code=status, url=absu, final_url=final,
            history=history, headers=headers, text=text, content=data,
            truncated=truncated, ms=ms, bytes=len(data),
        )
        self._record(method, absu, status, len(data), ms)
        return wr

    def _do(self, method: str, url: str, timeout: float | None = None, **kw: Any) -> WebResponse:
        absu = self._require_origin(url)
        self._require_budget()
        kw.setdefault("verify", self.verify)
        kw.setdefault("allow_redirects", True)
        start = time.monotonic()
        resp = self.session.request(method, absu, timeout=self.timeout if timeout is None else timeout, **kw)
        ms = (time.monotonic() - start) * 1000.0
        data, truncated = self._read_bounded(resp)
        return self._wrap(method, absu, resp, data, truncated, ms)

    # -- public API ----------------------------------------------------
    def get(self, url: str, params: dict[str, Any] | None = None, **kw: Any) -> WebResponse:
        if params:
            absu = self.resolve(url)
            parts = urllib.parse.urlsplit(absu)
            q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
            q.extend((str(k), str(v)) for k, v in params.items())
            url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(q), parts.fragment))
        return self._do("GET", url, **kw)

    def head(self, url: str, **kw: Any) -> WebResponse:
        """Safe HEAD fetch (same-origin + budget enforced)."""
        return self._do("HEAD", url, **kw)

    def options(self, url: str, **kw: Any) -> WebResponse:
        """Safe OPTIONS fetch (same-origin + budget enforced)."""
        return self._do("OPTIONS", url, **kw)

    def post_form(self, url: str, data: dict[str, Any] | None = None, csrf_preserve: bool = True, **kw: Any) -> WebResponse:
        payload = dict(data or {})
        if csrf_preserve:
            try:
                page = self.get(url)
                tokens = extract_hidden_tokens(page.text)
                for k, v in tokens.items():
                    payload.setdefault(k, v)
            except (ValueError, RuntimeError):
                raise
            except Exception:
                pass
        kw["data"] = payload
        return self._do("POST", url, **kw)

    def post_json(self, url: str, obj: Any = None, **kw: Any) -> WebResponse:
        kw["json"] = obj
        return self._do("POST", url, **kw)

    def sanitized_headers(self) -> dict[str, str]:
        out: dict[str, str] = {}
        try:
            items = dict(self.session.headers)
        except Exception:
            items = {}
        for k, v in items.items():
            if str(k).lower() in SENSITIVE_HEADERS:
                out[str(k)] = _redact(v)
            else:
                out[str(k)] = str(v)
        # cookies held in jar are sensitive too; surface redacted summary
        try:
            for c in self.session.cookies:
                out.setdefault(f"Cookie:{c.name}", _redact(getattr(c, "value", "")))
        except Exception:
            pass
        return out

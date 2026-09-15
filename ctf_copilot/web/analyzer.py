"""Passive web consolidation on shared WebSession (Phase 8, Task 14).

Single ``analyze(url, session=None, crawl=0, budget=None)`` + ``render()``
producing ONE report. GET-only, same-origin, bounded. No fuzzing/POST.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Any

from .endpoints import extract
from .headers import audit as audit_headers
from ..crypto.formats.jwt import decode as decode_jwt, looks as looks_jwt

MAX_SCRIPTS = 5
MAX_SOURCEMAPS = 3

SECRET_PATTERNS = [
    re.compile(r'(?i)(?:aws[_-]?secret|aws[_-]?access|api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["\']([^"\']{4,200})["\']'),
    re.compile(r'(?i)bearer\s+([A-Za-z0-9._~+/-]{12,})'),
    re.compile(r'AKIA[0-9A-Z]{12,20}'),
    re.compile(r'(?i)x-api-key\s*[:=]\s*["\']?([^"\'\s;,]{6,120})'),
]

SOURCEMAP_RE = re.compile(r'sourceMappingURL\s*=\s*([^\s\'"\)]+\.map)', re.I)
DOC_COOKIE_RE = re.compile(r'document\.cookie', re.I)
COOKIE_PAIR_RE = re.compile(r'([A-Za-z0-9_!$#%&\'*+\-.^`|~]+)\s*=\s*([^;,\s]+)')

AUTH_HINT_SUBSTRS = ("/admin", "/login", "/debug", "/api", "/graphql", "/server-status")

TECH_HEADER_KEYS = (
    "server", "x-powered-by", "x-aspnet-version", "x-generator",
    "via", "x-server", "x-backend",
)


class Parser(HTMLParser):
    """Extended HTML parser: links, scripts, forms+hidden, comments, inline JS."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.comments: list[str] = []
        self.inline_js: list[str] = []
        self.current: dict[str, Any] | None = None
        self._in_script = False

    def handle_comment(self, d):
        self.comments.append(d.strip())

    def handle_starttag(self, t, attrs):
        a = dict(attrs)
        tl = t.lower()
        if tl == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tl == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tl == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tl == "script":
            self._in_script = True
        elif tl == "form":
            self.current = {
                "action": a.get("action", ""),
                "method": (a.get("method", "GET") or "GET").upper(),
                "inputs": [],
                "hidden": {},
            }
            self.forms.append(self.current)
        elif tl == "input" and self.current is not None:
            name = a.get("name")
            if name:
                self.current["inputs"].append(name)
                itype = (a.get("type") or "").lower()
                if itype == "hidden":
                    self.current["hidden"][name] = a.get("value", "")

    def handle_endtag(self, t):
        tl = t.lower()
        if tl == "form":
            self.current = None
        elif tl == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script and data and data.strip():
            self.inline_js.append(data)


def _redact_secret(value: str) -> str:
    v = str(value)
    if len(v) <= 4:
        return "***"
    return v[:4] + "***"


def _split_joined_set_cookie(line: str) -> list[str]:
    """Split comma-joined Set-Cookie values without breaking Expires dates."""
    # Split on commas that start a new cookie (token=...). The comma inside
    # `Expires=Wed, 21 Oct ...` is followed by a date, not `token=`, so it survives.
    return [c.strip() for c in re.split(
        r',\s*(?=[A-Za-z0-9_!#$%&\'*+\-.^`|~]+\s*=)', line) if c.strip()]


def _parse_set_cookie(headers: dict[str, str]) -> list[tuple[str, str, dict[str, str]]]:
    out: list[tuple[str, str, dict[str, str]]] = []
    raw_vals: list[str] = []
    for k, v in (headers or {}).items():
        if str(k).lower() == "set-cookie":
            if isinstance(v, (list, tuple)):
                raw_vals.extend(str(x) for x in v)
            else:
                raw_vals.append(str(v))
    for raw in raw_vals:
        for line in str(raw).splitlines() or [str(raw)]:
            line = line.strip()
            if not line:
                continue
            for chunk in _split_joined_set_cookie(line):
                parts = [p.strip() for p in chunk.split(";")]
                if not parts:
                    continue
                name, _, val = parts[0].partition("=")
                name = name.strip().strip('"')
                if not name:
                    continue
                val = val.strip().strip('"')
                # Validate with SimpleCookie so garbage chunks are skipped.
                try:
                    jar = SimpleCookie()
                    jar.load(f"{name}={val}")
                    if name not in jar:
                        continue
                except Exception:
                    continue
                attrs: dict[str, str] = {}
                for p in parts[1:]:
                    ak, _, av = p.partition("=")
                    ak = ak.strip().lower()
                    if not ak:
                        continue
                    attrs[ak] = av.strip().strip('"') if av else "true"
                out.append((name, val.strip(), attrs))
    return out


def _same_origin(base_origin: tuple[str, str], absu: str) -> bool:
    try:
        p = urllib.parse.urlsplit(absu)
        if p.scheme not in ("http", "https"):
            return False
        return (p.scheme, p.netloc) == base_origin
    except Exception:
        return False


def _can_fetch(sess: Any, base_origin: tuple[str, str], url: str) -> bool:
    try:
        if sess is not None and hasattr(sess, "can_fetch"):
            return bool(sess.can_fetch(url))
    except Exception:
        pass
    try:
        absu = urllib.parse.urljoin(getattr(sess, "base_url", ""), url) if sess is not None else url
        return _same_origin(base_origin, absu)
    except Exception:
        return False


def _try_get(sess: Any, url: str):
    try:
        return sess.get(url)
    except (ValueError, RuntimeError):
        raise
    except Exception:
        return None


def analyze(url: str, session: Any = None, crawl: int = 0, budget: Any = None) -> dict[str, Any]:
    """Passive analysis via shared WebSession. GET-only, same-origin, bounded.

    Budget enforcement: ``WebSession.max_requests`` is the enforcer. Every
    recorded request appends to ``session.ledger`` and ``_require_budget``
    raises ``RuntimeError`` once ``len(ledger) >= max_requests``. Callers may
    pass a shared ``budget`` counter, but caps are enforced by ``max_requests``.
    """
    from .session import WebSession as _WS

    own_session = False
    if session is None:
        session = _WS(base_url=url, budget=budget)
        own_session = True
    else:
        if budget is not None:
            try:
                if getattr(session, "budget", None) is None:
                    session.budget = budget
            except Exception:
                pass
    try:
        crawl_n = max(0, int(crawl or 0))
    except Exception:
        crawl_n = 0

    try:
        base_origin = tuple(session.origin)  # type: ignore[attr-defined]
    except Exception:
        p0 = urllib.parse.urlsplit(url if url.startswith(("http://", "https://")) else "http://" + url)
        base_origin = (p0.scheme, p0.netloc)

    # -- main fetch --------------------------------------------------
    main = _try_get(session, url)
    if main is None:
        raise RuntimeError(f"passive fetch failed for {url!r}")
    status = int(getattr(main, "status", getattr(main, "status_code", 0)) or 0)
    final = str(getattr(main, "final_url", getattr(main, "url", url)) or url)
    headers = dict(getattr(main, "headers", {}) or {})
    body = str(getattr(main, "text", "") or "")
    history = list(getattr(main, "history", []) or [])
    redirect_chain = list(history) + ([final] if final not in history else [])

    p = Parser()
    try:
        p.feed(body)
    except Exception:
        pass

    links: list[str] = list(p.links)
    scripts: list[str] = list(p.scripts)
    forms: list[dict[str, Any]] = list(p.forms)
    comments: list[str] = list(p.comments)
    inline_js: list[str] = list(p.inline_js)

    endpoints: list[str] = list(extract(body))
    for chunk in inline_js:
        for e in extract(chunk):
            if e not in endpoints:
                endpoints.append(e)

    # -- bounded static scripts (don't count as pages) ---------------
    script_endpoints: dict[str, list[str]] = {}
    script_texts: dict[str, str] = {}
    for src in scripts[:MAX_SCRIPTS]:
        try:
            if not _can_fetch(session, base_origin, urllib.parse.urljoin(final, src)):
                continue
            r = _try_get(session, urllib.parse.urljoin(final, src))
            if r is None:
                continue
            js = str(getattr(r, "text", "") or "")
            script_texts[src] = js
            found = extract(js)
            if found:
                script_endpoints[src] = found
                for e in found:
                    if e not in endpoints:
                        endpoints.append(e)
        except (ValueError, RuntimeError):
            continue
        except Exception:
            continue

    # -- source maps -------------------------------------------------
    sourcemaps: dict[str, str] = {}
    map_urls: list[str] = []
    for blob in [body] + list(inline_js) + list(script_texts.values()):
        for m in SOURCEMAP_RE.findall(blob or ""):
            if m not in map_urls:
                map_urls.append(m)
    for mu in map_urls[:MAX_SOURCEMAPS]:
        try:
            absu = urllib.parse.urljoin(final, mu)
            if not _can_fetch(session, base_origin, absu):
                continue
            r = _try_get(session, absu)
            if r is None:
                continue
            txt = str(getattr(r, "text", "") or "")
            sourcemaps[mu] = txt[:2000]
        except (ValueError, RuntimeError):
            continue
        except Exception:
            continue

    # -- cookies + JWT -----------------------------------------------
    cookies: list[tuple[str, str]] = []
    try:
        jar = getattr(getattr(session, "session", None), "cookies", None)
        if jar is not None:
            for c in jar:
                try:
                    cookies.append((str(c.name), str(getattr(c, "value", ""))))
                except Exception:
                    continue
    except Exception:
        pass
    cookie_details = _parse_set_cookie(headers)
    for name, val, _attrs in cookie_details:
        if not any(k == name for k, _ in cookies):
            cookies.append((name, val))
    # document.cookie pairs in JS as extra signal (values only, never verify)
    doc_cookie_vals: list[str] = []
    for blob in [body] + list(inline_js) + list(script_texts.values()):
        if DOC_COOKIE_RE.search(blob or ""):
            for m in COOKIE_PAIR_RE.finditer(blob or ""):
                doc_cookie_vals.append(m.group(2))
    jwts: list[tuple[str, Any]] = []
    seen_jwt: set[str] = set()
    for name, val in cookies + [(f"document.cookie:{i}", v) for i, v in enumerate(doc_cookie_vals)]:
        try:
            if val and looks_jwt(val) and val not in seen_jwt:
                seen_jwt.add(val)
                try:
                    jwts.append((name, decode_jwt(val)))
                except Exception:
                    continue
        except Exception:
            continue

    # -- secrets (clues only, redacted at render) --------------------
    secrets: list[str] = []
    for blob in [body] + list(inline_js) + list(script_texts.values()):
        for pat in SECRET_PATTERNS:
            try:
                for m in pat.findall(blob or ""):
                    s = m if isinstance(m, str) else (m[0] if m else "")
                    if s and s not in secrets:
                        secrets.append(s)
            except Exception:
                continue

    # -- passive metadata within budget ------------------------------
    robots_txt = ""
    sitemap_txt = ""
    security_txt = ""
    for path, slot in (("/robots.txt", "robots"), ("/sitemap.xml", "sitemap"),
                       ("/.well-known/security.txt", "security")):
        try:
            r = _try_get(session, path)
            if r is None:
                continue
            if int(getattr(r, "status", getattr(r, "status_code", 0)) or 0) == 200:
                txt = str(getattr(r, "text", "") or "")
                if slot == "robots":
                    robots_txt = txt[:4000]
                elif slot == "sitemap":
                    sitemap_txt = txt[:4000]
                else:
                    security_txt = txt[:4000]
        except (ValueError, RuntimeError):
            continue
        except Exception:
            continue

    # -- crawl N (same-origin GET-only) -------------------------------
    crawled: list[str] = [final]
    crawled_bodies: list[str] = [body]
    if crawl_n > 0:
        seen_urls: set[str] = {final}
        try:
            seen_urls.add(str(getattr(main, "url", final)))
        except Exception:
            pass
        queue: list[str] = []
        for lk in links + endpoints:
            try:
                absu = urllib.parse.urljoin(final, lk)
                if _can_fetch(session, base_origin, absu) and absu not in seen_urls:
                    queue.append(absu)
            except Exception:
                continue
        while queue and (len(crawled) - 1) < crawl_n:
            nxt = queue.pop(0)
            if nxt in seen_urls:
                continue
            seen_urls.add(nxt)
            try:
                r = _try_get(session, nxt)
            except (ValueError, RuntimeError):
                continue
            if r is None:
                continue
            try:
                f2 = str(getattr(r, "final_url", getattr(r, "url", nxt)) or nxt)
            except Exception:
                f2 = nxt
            crawled.append(f2)
            txt2 = str(getattr(r, "text", "") or "")
            crawled_bodies.append(txt2)
            try:
                p2 = Parser()
                p2.feed(txt2)
            except Exception:
                p2 = None
            if p2 is not None:
                for lk in (p2.links + extract(txt2)):
                    try:
                        abs2 = urllib.parse.urljoin(f2, lk)
                        if _can_fetch(session, base_origin, abs2) and abs2 not in seen_urls and abs2 not in queue:
                            queue.append(abs2)
                    except Exception:
                        continue
                for e in extract(txt2):
                    if e not in endpoints:
                        endpoints.append(e)
                for c in p2.comments:
                    if c not in comments:
                        comments.append(c)
                for f in p2.forms:
                    forms.append(f)

    # -- tech hints + audit ------------------------------------------
    tech_hints: list[str] = []
    low = {str(k).lower(): str(v) for k, v in headers.items()}
    for k in TECH_HEADER_KEYS:
        if k in low and low[k]:
            tech_hints.append(f"{k}: {low[k][:120]}")
    if not tech_hints:
        tech_hints.append("server/x-powered-by: (not disclosed)")
    try:
        sec_rows = audit_headers(headers, final.startswith("https://"))
    except Exception:
        sec_rows = []
    cookie_flags: list[str] = []
    for name, _v, attrs in cookie_details:
        flags = []
        for f in ("httponly", "secure", "samesite"):
            if f in attrs:
                flags.append(f"{f}={attrs[f]}")
        cookie_flags.append(f"{name}: " + (", ".join(flags) if flags else "(no flags)"))

    # -- auth/admin/debug hints --------------------------------------
    auth_hints: list[str] = []
    for cand in links + endpoints + [e for rows in script_endpoints.values() for e in rows]:
        try:
            cl = str(cand).lower()
            if any(s in cl for s in AUTH_HINT_SUBSTRS) and cand not in auth_hints:
                auth_hints.append(str(cand))
        except Exception:
            continue

    # ledger snapshot
    try:
        ledger = list(getattr(session, "ledger", []) or [])
    except Exception:
        ledger = []

    void = own_session  #inery to keep linters quiet about unused
    _ = void

    return {
        "status": status,
        "final": final,
        "final_url": final,
        "headers": headers,
        "history": history,
        "redirect_chain": redirect_chain,
        "comments": comments,
        "forms": forms,
        "scripts": scripts,
        "links": links,
        "endpoints": endpoints,
        "script_endpoints": script_endpoints,
        "script_texts": {k: v[:2000] for k, v in script_texts.items()},
        "sourcemaps": sourcemaps,
        "cookies": cookies,
        "cookie_details": cookie_details,
        "cookie_flags": cookie_flags,
        "jwt": jwts,
        "secrets": secrets,
        "tech_hints": tech_hints,
        "security_audit": sec_rows,
        "auth_hints": auth_hints,
        "robots": robots_txt,
        "sitemap": sitemap_txt,
        "security_txt": security_txt,
        "crawled": crawled,
        "ledger": ledger,
    }


def render(info: dict[str, Any]) -> str:
    lines = ["WEB ANALYSIS", "============",
             f"Status: {info.get('status')}", f"Final URL: {info.get('final', info.get('final_url', ''))}"]
    chain = info.get("redirect_chain") or info.get("history") or []
    if chain:
        lines += ["", "Redirect chain:"] + [f"  {x}" for x in chain[:20]]
    hdrs = info.get("headers") or {}
    if hdrs:
        lines += ["", "Headers:"]
        for k, v in list(hdrs.items())[:30]:
            lk = str(k).lower()
            if lk in ("authorization", "cookie", "set-cookie", "x-api-key"):
                lines.append(f"  {k}: {_redact_secret(str(v))}")
            else:
                lines.append(f"  {k}: {str(v)[:200]}")
    if info.get("tech_hints"):
        lines += ["", "Technology hints:"] + [f"  {x}" for x in info["tech_hints"][:20]]
    if info.get("security_audit"):
        lines += ["", "Security header audit:"] + [f"  {x}" for x in info["security_audit"][:20]]
    # backward-compat sections (titles preserved)
    if info.get("comments"):
        lines += ["", "HTML comments:"] + [f"  {x}"[:300] for x in info["comments"][:40]]
    if info.get("forms"):
        lines += ["", "Forms:"]
        for f in info["forms"][:40]:
            try:
                lines.append(f"  {f.get('method', 'GET')} {f.get('action', '')} inputs={f.get('inputs', [])}")
                hid = f.get("hidden") or {}
                if hid:
                    lines.append(f"    hidden: {sorted(hid.keys())}")
            except Exception:
                lines.append(f"  {f}")
    if info.get("cookies"):
        lines += ["", "Cookies:"] + [f"  {k}={_redact_secret(v)}" for k, v in info["cookies"][:40]]
    if info.get("cookie_flags"):
        lines += ["", "Cookie attributes:"] + [f"  {x}" for x in info["cookie_flags"][:40]]
    if info.get("scripts"):
        lines += ["", "Scripts:"] + [f"  {x}" for x in info["scripts"][:40]]
    if info.get("links"):
        lines += ["", "Links:"] + [f"  {x}" for x in info["links"][:40]]
    if info.get("endpoints"):
        lines += ["", "Endpoints:"] + [f"  {x}" for x in info["endpoints"][:40]]
    if info.get("script_endpoints"):
        lines += ["", "Endpoints from JavaScript:"]
        for s, rows in info["script_endpoints"].items():
            lines += [f"  {s}"] + [f"    {x}" for x in rows]
    if info.get("sourcemaps"):
        lines += ["", "Source maps:"]
        for k, v in info["sourcemaps"].items():
            lines.append(f"  {k} ({len(str(v))} chars)")
    if info.get("jwt"):
        lines += ["", "JWT-like cookies:"] + [f"  {k}: {json.dumps(v)}" for k, v in info["jwt"]]
    if info.get("secrets"):
        lines += ["", "Secret-looking strings (clues only; verify context):"]
        for s in info["secrets"][:30]:
            lines.append(f"  {_redact_secret(s)}")
    if info.get("auth_hints"):
        lines += ["", "Auth/admin/debug hints:"] + [f"  {x}" for x in info["auth_hints"][:40]]
    if info.get("robots"):
        lines += ["", "robots.txt:"] + [f"  {x}" for x in str(info["robots"]).splitlines()[:20]]
    if info.get("sitemap"):
        lines += ["", "sitemap.xml:"] + [f"  {x}"[:200] for x in str(info["sitemap"]).splitlines()[:20]]
    if info.get("security_txt"):
        lines += ["", "security.txt:"] + [f"  {x}" for x in str(info["security_txt"]).splitlines()[:10]]
    if info.get("crawled") and len(info["crawled"]) > 1:
        lines += ["", "Crawled pages:"] + [f"  {x}" for x in info["crawled"][:20]]
    if info.get("ledger") is not None:
        try:
            n = len(info.get("ledger") or [])
            if n:
                lines += ["", f"Requests (passive, GET-only): {n}"]
        except Exception:
            pass
    lines += ["", "Passive only: same-origin GET requests, no fuzzing or POST."]
    return "\n".join(lines)

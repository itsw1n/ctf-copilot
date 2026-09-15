from __future__ import annotations
import re, urllib.parse
from .endpoints import extract

SECRET_PATTERNS=[
    re.compile(r'(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*["\']([^"\']{6,120})["\']'),
    re.compile(r'(?i)bearer\s+([A-Za-z0-9._~+/-]{12,})'),
]
PARAM_RE=re.compile(r'(?:(?:[?&])|(?:params?\s*[:=]\s*\{)|(?:searchParams\.set\())([A-Za-z_][A-Za-z0-9_-]{1,40})')

def _redact(v: str) -> str:
    v = str(v)
    return "***" if len(v) <= 4 else v[:4] + "***"

def inspect(url: str, session=None) -> str:
    """JS triage via shared WebSession (GET-only). Backward-compat inspect(url)."""
    from .session import WebSession as _WS
    sess = session if session is not None else _WS(base_url=url)
    own = session is None
    try:
        try:
            r = sess.get(url)
        except Exception:
            return "JAVASCRIPT TRIAGE\n=================\nfetch failed"
        body = str(getattr(r, "text", "") or "")
        final = str(getattr(r, "final_url", getattr(r, "url", url)) or url)
        status = int(getattr(r, "status", getattr(r, "status_code", 0)) or 0)
    finally:
        _ = own
    eps=extract(body)
    params=sorted(set(PARAM_RE.findall(body)))
    secrets=[]
    for pat in SECRET_PATTERNS:
        secrets.extend(pat.findall(body))
    out=['JAVASCRIPT TRIAGE','=================',f'Status: {status}',f'URL: {final}']
    out += ['','Endpoints:']+([f'  {x}' for x in eps[:100]] or ['  (none found)'])
    out += ['','Parameter names:']+([f'  {x}' for x in params[:100]] or ['  (none found)'])
    red = [f'  {_redact(x)[:160]}' for x in secrets[:30]] or ['  (none found)']
    out += ['','Secret-looking strings (clues only; verify context):']+red
    return '\n'.join(out)

def params_from_page(url: str, session=None) -> list[str]:
    from .analyzer import analyze as _analyze
    info=_analyze(url, session=session, crawl=0)
    out=[]
    for form in info['forms']:
        out.extend(x for x in form.get('inputs',[]) if x)
    for ep in info['endpoints']+[x for rows in info['script_endpoints'].values() for x in rows]:
        try:
            out.extend(urllib.parse.parse_qs(urllib.parse.urlsplit(ep).query).keys())
        except Exception: pass
    return sorted(set(out))

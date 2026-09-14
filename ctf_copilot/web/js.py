from __future__ import annotations
import re, urllib.parse
from .client import fetch
from .analyzer import analyze
from .endpoints import extract

SECRET_PATTERNS=[
    re.compile(r'(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*["\']([^"\']{6,120})["\']'),
    re.compile(r'(?i)bearer\s+([A-Za-z0-9._~+/-]{12,})'),
]
PARAM_RE=re.compile(r'(?:(?:[?&])|(?:params?\s*[:=]\s*\{)|(?:searchParams\.set\())([A-Za-z_][A-Za-z0-9_-]{1,40})')

def inspect(url: str) -> str:
    status,final,headers,body,_=fetch(url)
    eps=extract(body)
    params=sorted(set(PARAM_RE.findall(body)))
    secrets=[]
    for pat in SECRET_PATTERNS:
        secrets.extend(pat.findall(body))
    out=['JAVASCRIPT TRIAGE','=================',f'Status: {status}',f'URL: {final}']
    out += ['','Endpoints:']+([f'  {x}' for x in eps[:100]] or ['  (none found)'])
    out += ['','Parameter names:']+([f'  {x}' for x in params[:100]] or ['  (none found)'])
    out += ['','Secret-looking strings (clues only; verify context):']+([f'  {x[:160]}' for x in secrets[:30]] or ['  (none found)'])
    return '\n'.join(out)

def params_from_page(url: str) -> list[str]:
    info=analyze(url)
    out=[]
    for form in info['forms']:
        out.extend(x for x in form.get('inputs',[]) if x)
    for ep in info['endpoints']+[x for rows in info['script_endpoints'].values() for x in rows]:
        try:
            out.extend(urllib.parse.parse_qs(urllib.parse.urlsplit(ep).query).keys())
        except Exception: pass
    return sorted(set(out))

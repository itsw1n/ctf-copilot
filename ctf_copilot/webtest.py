from __future__ import annotations

import re
import urllib.parse
import urllib.request
from dataclasses import dataclass

USER_AGENT='CTF-Copilot/0.5 authorized-security-test'
SQL_ERROR=re.compile(r'(sql syntax|mysql|sqlite|postgresql|unterminated quoted|string.*sql|ora-\d+|odbc|database error)',re.I)


def _request(url: str, method: str='GET', timeout: int=8) -> tuple[int,dict[str,str],str]:
    req=urllib.request.Request(url,method=method,headers={'User-Agent':USER_AGENT})
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r:
            body=r.read(700_000).decode(r.headers.get_content_charset() or 'utf-8','replace')
            return r.status,dict(r.headers.items()),body
    except urllib.error.HTTPError as e:
        body=e.read(700_000).decode(e.headers.get_content_charset() or 'utf-8','replace')
        return e.code,dict(e.headers.items()),body


def header_audit(url: str) -> list[str]:
    st,h,_=_request(url)
    low={k.lower():v for k,v in h.items()}
    wanted=['content-security-policy','x-content-type-options','referrer-policy','permissions-policy']
    out=[f'Status: {st}']
    for k in wanted:
        out.append(f'{k}: {"present" if k in low else "missing"}')
    if url.lower().startswith('https://'):
        out.append(f'strict-transport-security: {"present" if "strict-transport-security" in low else "missing"}')
    return out


def method_probe(url: str) -> list[str]:
    out=[]
    for method in ('GET','HEAD','OPTIONS','POST','PUT','DELETE'):
        try:
            st,_,_=_request(url,method=method)
            out.append(f'{method:<7} {st}')
        except Exception as exc:
            out.append(f'{method:<7} error: {exc.__class__.__name__}')
    return out


def _mutate_query(url: str, value: str) -> list[tuple[str,str]]:
    u=urllib.parse.urlsplit(url)
    q=urllib.parse.parse_qsl(u.query,keep_blank_values=True)
    out=[]
    for idx,(k,v) in enumerate(q):
        nq=q.copy();nq[idx]=(k,value)
        nu=urllib.parse.urlunsplit((u.scheme,u.netloc,u.path,urllib.parse.urlencode(nq),u.fragment))
        out.append((k,nu))
    return out


def reflected_xss_probe(url: str) -> list[str]:
    marker='CTFCP_XSS_9f31<svg/onload=alert(1)>'
    rows=[]
    for param,nu in _mutate_query(url,marker):
        try:
            st,_,body=_request(nu)
            reflected=marker in body
            escaped=('CTFCP_XSS_9f31&lt;svg' in body or 'CTFCP_XSS_9f31%3Csvg' in body)
            if reflected:
                rows.append(f'{param}: raw marker reflected (status {st}) - inspect context manually')
            elif escaped:
                rows.append(f'{param}: marker reflected but appears escaped (status {st})')
            else:
                rows.append(f'{param}: no reflection observed (status {st})')
        except Exception as exc:
            rows.append(f'{param}: error {exc}')
    return rows or ['No query parameters found; supply a URL containing ?param=value.']


def sqli_probe(url: str) -> list[str]:
    payload="'"
    rows=[]
    try:
        base_st,_,base=_request(url)
    except Exception as exc:
        return [f'Baseline request failed: {exc}']
    for param,nu in _mutate_query(url,payload):
        try:
            st,_,body=_request(nu)
            err=bool(SQL_ERROR.search(body))
            delta=abs(len(body)-len(base))
            signal=[]
            if err: signal.append('SQL-like error text')
            if st>=500 and base_st<500: signal.append(f'status changed {base_st}->{st}')
            if delta>max(120, int(len(base)*0.20)): signal.append(f'body-size delta {delta}')
            rows.append(f'{param}: ' + (', '.join(signal) if signal else 'no obvious indicator'))
        except Exception as exc:
            rows.append(f'{param}: error {exc}')
    return rows or ['No query parameters found; supply a URL containing ?param=value.']


def run_tests(url: str, headers=False, methods=False, xss=False, sqli=False) -> str:
    selected=[]
    if headers:selected.append(('HEADERS',header_audit(url)))
    if methods:selected.append(('METHODS',method_probe(url)))
    if xss:selected.append(('XSS REFLECTION PROBE',reflected_xss_probe(url)))
    if sqli:selected.append(('SQLI INDICATOR PROBE',sqli_probe(url)))
    if not selected:
        selected=[('HEADERS',header_audit(url)),('METHODS',method_probe(url))]
    out=['AUTHORIZED WEB TEST','===================',f'Target: {url}']
    for title,rows in selected:
        out += ['',f'[{title}]']+[f'  {r}' for r in rows]
    out += ['', 'Note: findings are indicators, not proof. Confirm manually before concluding a vulnerability exists.']
    return '\n'.join(out)

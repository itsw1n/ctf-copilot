from __future__ import annotations
import json
from .client import fetch
from .analyzer import analyze, render
from .headers import audit
from .probes.methods import probe as methods_probe
from .probes.xss import probe as xss_probe
from .probes.sqli import probe as sqli_probe
from ..crypto.formats.jwt import decode as decode_jwt

def register(sub):
    q=sub.add_parser('web',help='Web exploitation helpers'); sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('analyze',help='Passive page/forms/scripts/cookies/endpoints inspection'); z.add_argument('url'); z.set_defaults(fn=lambda a: print(render(analyze(a.url))))
    z=sp.add_parser('headers',help='Show response headers and security-header audit'); z.add_argument('url'); z.set_defaults(fn=lambda a: _headers(a.url))
    z=sp.add_parser('endpoints',help='Extract endpoint-like paths from HTML/JS'); z.add_argument('url'); z.set_defaults(fn=lambda a: _eps(a.url))
    z=sp.add_parser('jwt',help='Decode JWT header/payload'); z.add_argument('token'); z.set_defaults(fn=lambda a: print(json.dumps(decode_jwt(a.token),indent=2)))
    z=sp.add_parser('compare',help='Compare status/body size for two URLs'); z.add_argument('url1'); z.add_argument('url2'); z.set_defaults(fn=lambda a: _compare(a.url1,a.url2))
    z=sp.add_parser('test',help='Controlled active probes; authorization confirmation required'); z.add_argument('url'); z.add_argument('--confirm-authorized',action='store_true'); z.add_argument('--headers',action='store_true'); z.add_argument('--methods',action='store_true'); z.add_argument('--xss',action='store_true'); z.add_argument('--sqli',action='store_true'); z.set_defaults(fn=_test)
def _headers(url):
    st,_,h,_,_=fetch(url); print(f'Status: {st}'); [print(f'{k}: {v}') for k,v in h.items()]; print('\nSecurity header audit:'); [print('  '+x) for x in audit(h,url.startswith('https://'))]
def _eps(url):
    i=analyze(url); rows=i['endpoints']+[e for v in i['script_endpoints'].values() for e in v]; [print(x) for x in list(dict.fromkeys(rows)) or ['No endpoint-like paths found.']]
def _compare(a,b):
    x=fetch(a); y=fetch(b); print(f'A: status={x[0]} size={len(x[3])}\nB: status={y[0]} size={len(y[3])}')
def _test(a):
    if not a.confirm_authorized: raise SystemExit('Refusing active probes without --confirm-authorized. Use only on CTF targets or systems you are authorized to test.')
    selected=[]
    if a.headers or not any((a.headers,a.methods,a.xss,a.sqli)): selected.append(('HEADERS',audit(fetch(a.url)[2],a.url.startswith('https://'))))
    if a.methods or not any((a.headers,a.methods,a.xss,a.sqli)): selected.append(('METHODS',methods_probe(a.url)))
    if a.xss: selected.append(('XSS REFLECTION',xss_probe(a.url)))
    if a.sqli: selected.append(('SQLI INDICATORS',sqli_probe(a.url)))
    print('AUTHORIZED WEB TEST\n===================\nTarget: '+a.url)
    for title,rows in selected: print('\n['+title+']'); [print('  '+r) for r in rows]
    print('\nIndicators are not proof; confirm manually before concluding a vulnerability exists.')

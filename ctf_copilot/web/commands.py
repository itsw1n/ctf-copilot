from __future__ import annotations
import json
from .client import fetch
from .analyzer import analyze, render
from .headers import audit
from .js import inspect as js_inspect, params_from_page
from .playbook import map_target
from .source import inspect as source_inspect
from .probes.methods import probe as methods_probe
from .probes.xss import probe as xss_probe
from .probes.sqli import probe as sqli_probe
from ..crypto.formats.jwt import decode as decode_jwt

def register(sub):
    q=sub.add_parser('web',help='Inspect authorized CTF web applications',description='Use for web challenges: start passive, map endpoints/parameters, then use controlled active probes only when authorized.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('analyze',help='Passive first-pass web reconnaissance',description='Best first web command: inspect status, forms, comments, cookies, scripts and endpoint clues.'); z.add_argument('url'); z.set_defaults(fn=lambda a: print(render(analyze(a.url))))
    z=sp.add_parser('headers',help='Response/security-header audit',description='Use to inspect cookies/headers and identify missing defensive headers as clues.'); z.add_argument('url'); z.set_defaults(fn=lambda a: _headers(a.url))
    z=sp.add_parser('endpoints',help='Extract paths/API routes from HTML/JS',description='Use when hidden API/admin/debug routes may be referenced in frontend code.'); z.add_argument('url'); z.set_defaults(fn=lambda a: _eps(a.url))
    z=sp.add_parser('js',help='Inspect JavaScript for routes/params/secret-looking strings',description='Use when app.js/bundles may reveal hidden endpoints, parameter names, tokens, or developer clues.'); z.add_argument('url'); z.set_defaults(fn=lambda a: print(js_inspect(a.url)))
    z=sp.add_parser('params',help='List interesting parameter names',description='Use before Burp/manual testing to see what inputs and query parameters the app exposes.'); z.add_argument('url'); z.set_defaults(fn=lambda a: [print(x) for x in params_from_page(a.url)] or print('No parameter names found.'))
    z=sp.add_parser('map',help='Bounded passive same-origin crawler',description='Maps public links, scripts and endpoint clues without fuzzing or active probes.'); z.add_argument('url'); z.add_argument('--max-pages',type=int,default=12); z.set_defaults(fn=lambda a: print(map_target(a.url,max(1,min(a.max_pages,50)))))
    z=sp.add_parser('source',help='Statically inspect supplied web source',description='Find routes, risky sinks, secrets and authorization clues without executing source code.'); z.add_argument('path'); z.set_defaults(fn=lambda a: print(source_inspect(a.path)))
    z=sp.add_parser('jwt',help='Decode JWT header/payload',description='Decode a JWT for inspection. This does not verify or bypass its signature.'); z.add_argument('token'); z.set_defaults(fn=lambda a: print(json.dumps(decode_jwt(a.token),indent=2)))
    z=sp.add_parser('compare',help='Compare status/body size for two URLs',description='Use to compare two controlled requests and spot response differences.'); z.add_argument('url1'); z.add_argument('url2'); z.set_defaults(fn=lambda a: _compare(a.url1,a.url2))
    z=sp.add_parser('test',help='Controlled active indicators; authorization required',description='Run low-impact header/method/reflection/SQL-error indicators only on CTF, owned, or explicitly authorized targets.'); z.add_argument('url'); z.add_argument('--confirm-authorized',action='store_true'); z.add_argument('--headers',action='store_true'); z.add_argument('--methods',action='store_true'); z.add_argument('--xss',action='store_true'); z.add_argument('--sqli',action='store_true'); z.set_defaults(fn=_test)

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

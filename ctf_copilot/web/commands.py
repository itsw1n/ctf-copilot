from __future__ import annotations
import json
from .analyzer import analyze, render
from .headers import audit
from .js import inspect as js_inspect, params_from_page
from .playbook import map_target
from .session import WebSession
from .source import inspect as source_inspect
from .cbc import bitflip as cbc_bitflip, acquire_cookie
from .probes.methods import probe as methods_probe
from .probes.xss import probe as xss_probe
from .probes.sqli import probe as sqli_probe
from .probes.idor import probe as idor_probe
from .probes.traversal import probe as traversal_probe
from .probes.ssti import probe as ssti_probe
from .probes.command import probe as command_probe
from .probes.redirect import probe as redirect_probe
from ..crypto.formats.jwt import decode as decode_jwt

GLOBAL_MAX = 40
TECH_MAX = 6


def register(sub):
    q=sub.add_parser('web',help='Inspect authorized CTF web applications',description='Use for web challenges: start passive, map endpoints/parameters, then use controlled active probes only when authorized.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('analyze',help='Passive first-pass web reconnaissance',description='Best first web command: inspect status, forms, comments, cookies, scripts and endpoint clues.'); z.add_argument('url'); z.add_argument('--crawl',type=int,default=0,help='Same-origin GET-only pages to follow (default 0)'); z.add_argument('--header',action='append',default=[],help="Extra header 'Name: value' (repeatable)"); z.add_argument('--cookie',action='append',default=[],help="Extra cookie 'name=value' (repeatable)"); z.set_defaults(fn=_analyze_cmd)
    z=sp.add_parser('headers',help='Response/security-header audit',description='Use to inspect cookies/headers and identify missing defensive headers as clues.'); z.add_argument('url'); z.set_defaults(fn=lambda a: _headers(a.url))
    z=sp.add_parser('endpoints',help='Extract paths/API routes from HTML/JS',description='Use when hidden API/admin/debug routes may be referenced in frontend code.'); z.add_argument('url'); z.set_defaults(fn=lambda a: _eps(a.url))
    z=sp.add_parser('js',help='Inspect JavaScript for routes/params/secret-looking strings',description='Use when app.js/bundles may reveal hidden endpoints, parameter names, tokens, or developer clues.'); z.add_argument('url'); z.set_defaults(fn=lambda a: print(js_inspect(a.url)))
    z=sp.add_parser('params',help='List interesting parameter names',description='Use before Burp/manual testing to see what inputs and query parameters the app exposes.'); z.add_argument('url'); z.set_defaults(fn=lambda a: [print(x) for x in params_from_page(a.url)] or print('No parameter names found.'))
    z=sp.add_parser('map',help='Bounded passive same-origin crawler',description='Maps public links, scripts and endpoint clues without fuzzing or active probes.'); z.add_argument('url'); z.add_argument('--max-pages',type=int,default=12); z.set_defaults(fn=lambda a: print(map_target(a.url,max(1,min(a.max_pages,50)))))
    z=sp.add_parser('source',help='Statically inspect supplied web source',description='Find routes, risky sinks, secrets and authorization clues without executing source code.'); z.add_argument('path'); z.set_defaults(fn=lambda a: print(source_inspect(a.path)))
    z=sp.add_parser('cbc-bitflip',help='Try bounded CBC cookie bit flips on an authorized CTF',description='For double-Base64 CBC cookie challenges such as picoCTF More Cookies. Sends modified cookies only after confirmation.'); z.add_argument('url'); z.add_argument('cookie',nargs='?',help='Cookie value, unless --auto-cookie obtains a fresh one'); z.add_argument('--auto-cookie',action='store_true',help='Fetch a fresh named cookie from the target first'); z.add_argument('--cookie-name',default='auth_name'); z.add_argument('--max-attempts',type=int,default=256); z.add_argument('--confirm-authorized',action='store_true'); z.set_defaults(fn=_cbc)
    z=sp.add_parser('jwt',help='Decode JWT header/payload',description='Decode a JWT for inspection. This does not verify or bypass its signature.'); z.add_argument('token'); z.set_defaults(fn=lambda a: print(json.dumps(decode_jwt(a.token),indent=2)))
    z=sp.add_parser('compare',help='Compare status/body size for two URLs',description='Use to compare two controlled requests and spot response differences.'); z.add_argument('url1'); z.add_argument('url2'); z.set_defaults(fn=lambda a: _compare(a.url1,a.url2))
    z=sp.add_parser('test',help='Controlled active indicators; authorization required',description='Run low-impact header/method/reflection/SQL-error indicators only on CTF, owned, or explicitly authorized targets.'); z.add_argument('url'); z.add_argument('--confirm-authorized',action='store_true'); z.add_argument('--headers',action='store_true'); z.add_argument('--methods',action='store_true'); z.add_argument('--xss',action='store_true'); z.add_argument('--sqli',action='store_true'); z.add_argument('--idor',action='store_true'); z.add_argument('--traversal',action='store_true'); z.add_argument('--ssti',action='store_true'); z.add_argument('--cmd',dest='cmd_probe',action='store_true'); z.add_argument('--redirect',action='store_true'); z.add_argument('--cookies',action='store_true'); z.set_defaults(fn=_test)
    # Specialists covered by `analyze`: hidden from --help listings, still runnable.
    from ..shared.args import hide_subcommands
    hide_subcommands(sp, 'endpoints', 'js', 'params', 'headers', 'map', 'jwt')

def _analyze_cmd(a):
    from .session import WebSession as _WS, parse_header, parse_cookie
    headers: dict[str, str] = {}
    for spec in getattr(a, "header", []) or []:
        try:
            k, v = parse_header(spec)
            headers[k] = v
        except Exception as exc:
            raise SystemExit(str(exc))
    cookies: dict[str, str] = {}
    for spec in getattr(a, "cookie", []) or []:
        try:
            k, v = parse_cookie(spec)
            cookies[k] = v
        except Exception as exc:
            raise SystemExit(str(exc))
    sess = _WS(base_url=a.url, headers=headers or None, cookies=cookies or None)
    print(render(analyze(a.url, session=sess, crawl=getattr(a, "crawl", 0) or 0)))

def _headers(url):
    sess = WebSession(base_url=url)
    try:
        resp = sess.get(url)
    except ValueError as exc:
        print(str(exc))
        return
    print(f'Status: {resp.status}')
    for k, v in resp.headers.items():
        print(f'{k}: {v}')
    print('\nSecurity header audit:')
    for x in audit(resp.headers, url.startswith('https://')):
        print('  '+x)

def _eps(url):
    i=analyze(url); rows=i['endpoints']+[e for v in i['script_endpoints'].values() for e in v]; [print(x) for x in list(dict.fromkeys(rows)) or ['No endpoint-like paths found.']]

def _compare(a,b):
    sess = WebSession(base_url=a, max_requests=10)
    try:
        from . import differential as _diff
        ra = _diff.fetch_bounded(sess, "GET", a)
        try:
            rb = _diff.fetch_bounded(sess, "GET", b)
        except ValueError:
            print(f"blocked cross-origin request for second URL: {b!r} (base {a})")
            print(f'A: status={ra.status} size={ra.body_len}')
            return
        cmp = _diff.compare(ra, rb)
        print(f'A: status={cmp["status_before"]} size={ra.body_len}\nB: status={cmp["status_after"]} size={rb.body_len}')
        if cmp.get("title_changed"):
            print(f'title: {cmp["title_before"]!r} -> {cmp["title_after"]!r}')
    except ValueError as exc:
        print(str(exc))

def _headers_rows(sess, url):
    from . import differential as _diff
    resp = _diff.fetch_bounded(sess, "GET", url)
    rows = audit(resp.headers, url.startswith('https://'))
    rows = list(rows) + ["handoff: curl -i URL to confirm headers; check Burp Proxy history."]
    return [r.replace("URL", url) for r in rows]

def _cookies_rows(sess, url):
    from . import differential as _diff
    from .analyzer import _parse_set_cookie
    resp = _diff.fetch_bounded(sess, "GET", url)
    details = _parse_set_cookie(resp.headers)
    if not details:
        return ["cookies: none observed (candidate only). handoff: check Burp Proxy cookies; curl -c/-b to retest."]
    rows = []
    for name, _v, attrs in details:
        flags = ", ".join(f"{k}={v}" for k, v in attrs.items()) or "(no flags)"
        rows.append(f"{name}: {flags} (candidate - missing flags are clues only, not proof)")
    rows.append("handoff: curl -b/-c to retest flags; inspect in Burp; gobuster/ffuf not needed for cookies.")
    return rows

def _run_safe(title, fn):
    try:
        return (title, fn())
    except ValueError as exc:
        return (title, [f"blocked: {exc}"])
    except RuntimeError as exc:
        return (title, [f"stopped: {exc} (budget cap; rerun with fewer techniques)"])

def _test(a):
    if not getattr(a, "confirm_authorized", False):
        raise SystemExit('Refusing active probes without --confirm-authorized. Use only on CTF targets or systems you are authorized to test.')
    flags = {
        'headers': bool(getattr(a, "headers", False)),
        'cookies': bool(getattr(a, "cookies", False)),
        'methods': bool(getattr(a, "methods", False)),
        'xss': bool(getattr(a, "xss", False)),
        'sqli': bool(getattr(a, "sqli", False)),
        'idor': bool(getattr(a, "idor", False)),
        'traversal': bool(getattr(a, "traversal", False)),
        'ssti': bool(getattr(a, "ssti", False)),
        'cmd': bool(getattr(a, "cmd_probe", getattr(a, "cmd", False))),
        'redirect': bool(getattr(a, "redirect", False)),
    }
    url = a.url
    if not any(flags.values()):
        print('AUTHORIZED WEB TEST\n===================\nTarget: '+url)
        print('\nNo technique selected - no requests sent. Would run (each max ~6 requests, global max ~40):')
        for name in ('headers', 'cookies', 'methods', 'xss', 'sqli', 'idor', 'traversal', 'ssti', 'cmd', 'redirect'):
            print(f'  --{name}: bounded {"header audit" if name=="headers" else "cookie audit" if name=="cookies" else name+" probe"}')
        print('\nRerun with --confirm-authorized plus technique flags, e.g.:')
        print(f'  ctf web test {url} --confirm-authorized --sqli --xss')
        print('\nSame-origin only; no file upload or state-changing posts.')
        return
    sess = WebSession(base_url=url, max_requests=GLOBAL_MAX)
    selected: list[tuple[str, list[str]]] = []
    if flags['headers']:
        selected.append(_run_safe('HEADERS', lambda: _headers_rows(sess, url)))
    if flags['cookies']:
        selected.append(_run_safe('COOKIES', lambda: _cookies_rows(sess, url)))
    if flags['methods']:
        selected.append(_run_safe('METHODS', lambda: methods_probe(url, session=sess, max_requests=TECH_MAX)))
    if flags['xss']:
        selected.append(_run_safe('XSS REFLECTION', lambda: xss_probe(url, session=sess, max_requests=TECH_MAX)))
    if flags['sqli']:
        selected.append(_run_safe('SQLI INDICATORS', lambda: sqli_probe(url, session=sess, max_requests=TECH_MAX)))
    if flags['idor']:
        selected.append(_run_safe('IDOR', lambda: idor_probe(url, session=sess, max_requests=TECH_MAX)))
    if flags['traversal']:
        selected.append(_run_safe('TRAVERSAL', lambda: traversal_probe(url, session=sess, max_requests=TECH_MAX)))
    if flags['ssti']:
        selected.append(_run_safe('SSTI', lambda: ssti_probe(url, session=sess, max_requests=TECH_MAX)))
    if flags['cmd']:
        selected.append(_run_safe('CMD', lambda: command_probe(url, session=sess, max_requests=TECH_MAX)))
    if flags['redirect']:
        selected.append(_run_safe('REDIRECT', lambda: redirect_probe(url, session=sess, max_requests=TECH_MAX)))
    print('AUTHORIZED WEB TEST\n===================\nTarget: '+url)
    for title, rows in selected:
        print('\n['+title+']')
        for r in rows:
            print('  '+r)
    print('\nIndicators are candidate/indicator unless a deterministic marker proves behavior; confirm manually before concluding a vulnerability exists.')
    print(f'Requests used: {len(sess.ledger)}/{GLOBAL_MAX} (same-origin GET/HEAD/OPTIONS only).')

def _cbc(a):
    if not a.confirm_authorized:
        raise SystemExit('Refusing CBC bit-flip requests without --confirm-authorized. Use only on your authorized CTF instance.')
    cookie=a.cookie
    if a.auto_cookie:
        cookie,message=acquire_cookie(a.url,a.cookie_name)
        if not cookie: raise SystemExit(message)
        print(message)
    if not cookie: raise SystemExit('Supply a cookie value or use --auto-cookie.')
    print(cbc_bitflip(a.url,cookie,a.cookie_name,max(1,min(a.max_attempts,2048)),print))

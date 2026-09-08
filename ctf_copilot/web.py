from __future__ import annotations

import base64
import json
import re
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.cookiejar import CookieJar


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
        self.forms = []
        self.comments = []
        self.current_form = None

    def handle_comment(self, data):
        self.comments.append(data.strip())

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])
        elif tag == 'script' and attrs.get('src'):
            self.scripts.append(attrs['src'])
        elif tag == 'form':
            self.current_form = {
                'action': attrs.get('action', ''),
                'method': attrs.get('method', 'GET').upper(),
                'inputs': [],
            }
            self.forms.append(self.current_form)
        elif tag == 'input' and self.current_form is not None:
            self.current_form['inputs'].append(attrs.get('name'))

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current_form = None


def jwt(token: str):
    parts = token.split('.')
    if len(parts) != 3:
        return None
    try:
        decoded = []
        for part in parts[:2]:
            part += '=' * ((4 - len(part) % 4) % 4)
            decoded.append(json.loads(base64.urlsafe_b64decode(part).decode()))
        return {'header': decoded[0], 'payload': decoded[1]}
    except Exception:
        return None


def fetch(url: str):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    request = urllib.request.Request(url, headers={'User-Agent': 'CTF-Copilot/0.5'})
    response = opener.open(request, timeout=10)
    body = response.read(2_000_000).decode(response.headers.get_content_charset() or 'utf-8', 'replace')
    return response.status, response.geturl(), dict(response.headers.items()), body, jar


def endpoints(text: str) -> list[str]:
    patterns = [
        re.compile(r'''["']((?:/api/|/graphql|/admin|/debug|/internal|/v\d+/)[A-Za-z0-9_./?=&%:#@+\-{}:]*)["']''', re.I),
        re.compile(r'''fetch\(\s*["']([^"']+)["']''', re.I),
        re.compile(r'''axios\.(?:get|post|put|patch|delete)\(\s*["']([^"']+)["']''', re.I),
    ]
    out = []
    for pattern in patterns:
        out.extend(pattern.findall(text))
    return list(dict.fromkeys(out))


def analyze(url: str):
    status, final, headers, body, jar = fetch(url)
    parser = PageParser()
    parser.feed(body)
    script_endpoints = {}
    for script in parser.scripts[:20]:
        try:
            _, _, _, js, _ = fetch(urllib.parse.urljoin(final, script))
            found = endpoints(js)
            if found:
                script_endpoints[script] = found
        except Exception:
            pass
    cookies = []
    jwts = []
    for cookie in jar:
        cookies.append((cookie.name, cookie.value))
        decoded = jwt(cookie.value)
        if decoded:
            jwts.append((cookie.name, decoded))
    return {
        'status': status,
        'final': final,
        'headers': headers,
        'comments': parser.comments,
        'forms': parser.forms,
        'scripts': parser.scripts,
        'endpoints': endpoints(body),
        'script_endpoints': script_endpoints,
        'cookies': cookies,
        'jwt': jwts,
    }


def render(info) -> str:
    lines = ['WEB ANALYSIS', '============', f"Status: {info['status']}", f"Final URL: {info['final']}"]
    if info['comments']:
        lines += ['', 'HTML comments:'] + [f'  {x}' for x in info['comments'][:20]]
    if info['forms']:
        lines += ['', 'Forms:'] + [f'  {x}' for x in info['forms']]
    if info['cookies']:
        lines += ['', 'Cookies:'] + [f'  {k}={v[:80]}' for k, v in info['cookies']]
    if info['jwt']:
        lines += ['', 'JWT-like cookies:'] + [f'  {k}: {json.dumps(v)}' for k, v in info['jwt']]
    if info['scripts']:
        lines += ['', 'Scripts:'] + [f'  {x}' for x in info['scripts']]
    if info['endpoints']:
        lines += ['', 'Endpoints:'] + [f'  {x}' for x in info['endpoints']]
    if info['script_endpoints']:
        lines += ['', 'Endpoints from JavaScript:']
        for script, rows in info['script_endpoints'].items():
            lines.append(f'  {script}')
            lines += [f'    {x}' for x in rows]
    return '\n'.join(lines)

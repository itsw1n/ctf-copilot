"""Bounded, passive, same-origin web mapping for authorized CTF targets."""
from __future__ import annotations
from collections import deque
from html.parser import HTMLParser
import re
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

from ..shared.flags import find_flags
from .endpoints import extract


class _Links(HTMLParser):
    def __init__(self): super().__init__(); self.urls=[]
    def handle_starttag(self, tag, attrs):
        value=dict(attrs).get('href' if tag=='a' else 'src' if tag in ('script','img') else '')
        if value: self.urls.append(value)


def map_target(url: str, max_pages: int = 12) -> str:
    """Fetch only public GET resources on the original origin; no fuzzing/probes."""
    if not url.startswith(('http://','https://')): url='http://'+url
    origin=urllib.parse.urlsplit(url)
    jar=CookieJar(); opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    queue=deque([url]); seen=set(); rows=[]; endpoints=set(); flags=[]
    while queue and len(seen)<max_pages:
        current=queue.popleft()
        if current in seen: continue
        parts=urllib.parse.urlsplit(current)
        if (parts.scheme,parts.netloc)!=(origin.scheme,origin.netloc): continue
        seen.add(current)
        try:
            req=urllib.request.Request(current,headers={'User-Agent':'CTF-Copilot/1.0'})
            with opener.open(req,timeout=10) as response:
                body=response.read(1_000_000).decode(response.headers.get_content_charset() or 'utf-8','replace')
                final=response.geturl(); rows.append(f'{response.status} {final} ({len(body)} bytes)')
        except Exception as exc:
            rows.append(f'error {current}: {exc}'); continue
        flags.extend(find_flags(body)); endpoints.update(extract(body))
        parser=_Links(); parser.feed(body)
        for value in parser.urls + extract(body):
            child=urllib.parse.urljoin(final,value)
            child_parts=urllib.parse.urlsplit(child)
            if (child_parts.scheme,child_parts.netloc)==(origin.scheme,origin.netloc) and child not in seen:
                queue.append(child)
    out=['PASSIVE WEB MAP','===============',f'Origin: {origin.scheme}://{origin.netloc}',f'Pages requested: {len(seen)}/{max_pages}','', 'Responses:']
    out += [f'  {x}' for x in rows]
    if endpoints: out += ['', 'Interesting endpoints:']+[f'  {x}' for x in sorted(endpoints)[:100]]
    if flags: out += ['', 'Possible flags:']+[f'  {x}' for x in dict.fromkeys(flags)]
    out += ['', 'This used only same-origin GET requests. For active tests, use `ctf web test <url> --confirm-authorized`.']
    return '\n'.join(out)

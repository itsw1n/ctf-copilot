from __future__ import annotations
import urllib.request
from http.cookiejar import CookieJar
USER_AGENT='CTF-Copilot/0.7'
def fetch(url: str):
    if not url.startswith(('http://','https://')): url='http://'+url
    jar=CookieJar(); opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    req=urllib.request.Request(url,headers={'User-Agent':USER_AGENT})
    with opener.open(req,timeout=10) as r:
        body=r.read(2_000_000).decode(r.headers.get_content_charset() or 'utf-8','replace')
        return r.status,r.geturl(),dict(r.headers.items()),body,jar

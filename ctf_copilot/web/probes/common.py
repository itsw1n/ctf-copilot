from __future__ import annotations
import urllib.error, urllib.request
UA='CTF-Copilot/0.7 authorized-security-test'
def request(url,method='GET',timeout=8):
    req=urllib.request.Request(url,method=method,headers={'User-Agent':UA})
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r: return r.status,dict(r.headers.items()),r.read(700_000).decode(r.headers.get_content_charset() or 'utf-8','replace')
    except urllib.error.HTTPError as e: return e.code,dict(e.headers.items()),e.read(700_000).decode(e.headers.get_content_charset() or 'utf-8','replace')

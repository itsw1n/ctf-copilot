from __future__ import annotations
import json, urllib.parse
from html.parser import HTMLParser
from .client import fetch
from .endpoints import extract
from ..crypto.formats.jwt import decode as decode_jwt, looks as looks_jwt
class Parser(HTMLParser):
    def __init__(self): super().__init__(); self.links=[]; self.scripts=[]; self.forms=[]; self.comments=[]; self.current=None
    def handle_comment(self,d): self.comments.append(d.strip())
    def handle_starttag(self,t,attrs):
        a=dict(attrs)
        if t=='a' and a.get('href'): self.links.append(a['href'])
        elif t=='script' and a.get('src'): self.scripts.append(a['src'])
        elif t=='form': self.current={'action':a.get('action',''),'method':a.get('method','GET').upper(),'inputs':[]}; self.forms.append(self.current)
        elif t=='input' and self.current is not None: self.current['inputs'].append(a.get('name'))
    def handle_endtag(self,t):
        if t=='form': self.current=None

def analyze(url: str):
    status,final,headers,body,jar=fetch(url); p=Parser(); p.feed(body); script_eps={}
    for src in p.scripts[:20]:
        try:
            _,_,_,js,_=fetch(urllib.parse.urljoin(final,src)); found=extract(js)
            if found: script_eps[src]=found
        except Exception: pass
    cookies=[]; jwts=[]
    for c in jar:
        cookies.append((c.name,c.value))
        if looks_jwt(c.value):
            try: jwts.append((c.name,decode_jwt(c.value)))
            except Exception: pass
    return {'status':status,'final':final,'headers':headers,'comments':p.comments,'forms':p.forms,'scripts':p.scripts,'endpoints':extract(body),'script_endpoints':script_eps,'cookies':cookies,'jwt':jwts}

def render(info):
    lines=['WEB ANALYSIS','============',f"Status: {info['status']}",f"Final URL: {info['final']}"]
    for key,label in [('comments','HTML comments'),('forms','Forms'),('cookies','Cookies'),('scripts','Scripts'),('endpoints','Endpoints')]:
        if info[key]: lines += ['',label+':']+[f'  {x}' for x in info[key][:40]]
    if info['script_endpoints']:
        lines += ['','Endpoints from JavaScript:']
        for s,rows in info['script_endpoints'].items(): lines += [f'  {s}']+[f'    {x}' for x in rows]
    if info['jwt']: lines += ['','JWT-like cookies:']+[f'  {k}: {json.dumps(v)}' for k,v in info['jwt']]
    return '\n'.join(lines)

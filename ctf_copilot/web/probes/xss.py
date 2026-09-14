import urllib.parse
from .common import request
def _mutate(url,value):
    u=urllib.parse.urlsplit(url); q=urllib.parse.parse_qsl(u.query,keep_blank_values=True); out=[]
    for i,(k,v) in enumerate(q):
        nq=q.copy(); nq[i]=(k,value); out.append((k,urllib.parse.urlunsplit((u.scheme,u.netloc,u.path,urllib.parse.urlencode(nq),u.fragment))))
    return out
def probe(url):
    marker='CTFCP_XSS_9f31<svg/onload=alert(1)>'; rows=[]
    for p,u in _mutate(url,marker):
        try:
            st,_,body=request(u); rows.append(f'{p}: '+('raw marker reflected - inspect context manually' if marker in body else 'no raw reflection observed')+f' (status {st})')
        except Exception as e: rows.append(f'{p}: error {e}')
    return rows or ['No query parameters found.']

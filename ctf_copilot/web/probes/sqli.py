import re, urllib.parse
from .common import request
ERR=re.compile(r'(sql syntax|mysql|sqlite|postgresql|unterminated quoted|string.*sql|ora-\d+|odbc|database error)',re.I)
def _mutate(url,value):
    u=urllib.parse.urlsplit(url); q=urllib.parse.parse_qsl(u.query,keep_blank_values=True); out=[]
    for i,(k,v) in enumerate(q):
        nq=q.copy(); nq[i]=(k,value); out.append((k,urllib.parse.urlunsplit((u.scheme,u.netloc,u.path,urllib.parse.urlencode(nq),u.fragment))))
    return out
def probe(url):
    bst,_,base=request(url); rows=[]
    for p,u in _mutate(url,"'"):
        try:
            st,_,body=request(u); sig=[]
            if ERR.search(body): sig.append('SQL-like error text')
            if st>=500 and bst<500: sig.append(f'status {bst}->{st}')
            if abs(len(body)-len(base))>max(120,int(len(base)*.2)): sig.append('large body-size change')
            rows.append(f'{p}: '+(', '.join(sig) if sig else 'no obvious indicator'))
        except Exception as e: rows.append(f'{p}: error {e}')
    return rows or ['No query parameters found.']

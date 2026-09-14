"""Small, deterministic RSA helpers for CTF parameters; no network oracle use."""
from __future__ import annotations
import math
import re

def _value(text: str, name: str) -> int | None:
    m=re.search(rf'(?im)^\s*{re.escape(name)}\s*=\s*(?:0x)?([0-9a-fA-F]+)',text)
    if not m: return None
    raw=m.group(1); return int(raw,16) if raw.lower().startswith('0x') or re.search(r'[a-f]',raw,re.I) else int(raw)

def _factor(n: int, limit: int=1_000_000) -> tuple[int,int] | None:
    if n%2==0: return 2,n//2
    top=min(math.isqrt(n),limit)
    for p in range(3,top+1,2):
        if n%p==0: return p,n//p
    return None

def _iroot(value: int, exponent: int) -> tuple[int,bool]:
    lo,hi=0,1
    while hi**exponent<=value: hi*=2
    while lo+1<hi:
        mid=(lo+hi)//2
        if mid**exponent<=value: lo=mid
        else: hi=mid
    return lo,lo**exponent==value

def solve(text: str) -> str:
    n,e,c=(_value(text,x) for x in ('n','e','c'))
    if None in (n,e,c): return 'RSA solver needs lines like: n = ..., e = ..., c = ...'
    assert n is not None and e is not None and c is not None
    out=['RSA WEAKNESS CHECK','==================',f'n bits: {n.bit_length()}',f'e: {e}']
    root,exact=_iroot(c,e) if e<=17 else (0,False)
    if exact:
        raw=root.to_bytes(max(1,(root.bit_length()+7)//8),'big')
        return '\n'.join(out+['Finding: c is an exact e-th power (textbook small-exponent RSA).',f'Plaintext bytes: {raw!r}'])
    factors=_factor(n)
    if not factors:
        return '\n'.join(out+['No factor found within the safe 1,000,000 trial-divisor limit.','Next: use a factorization tool only if the challenge evidence suggests a weak/factorable modulus.'])
    p,q=factors; phi=(p-1)*(q-1)
    try: d=pow(e,-1,phi)
    except ValueError: return '\n'.join(out+[f'Found p={p}, q={q}, but e has no inverse modulo phi.'])
    message=pow(c,d,n); raw=message.to_bytes(max(1,(message.bit_length()+7)//8),'big')
    return '\n'.join(out+[f'Finding: n factors as {p} × {q}.','Recovered plaintext bytes: '+repr(raw), 'Verify the decoded bytes match the event flag format.'])

from __future__ import annotations
import base64, json, re

def looks(token: str) -> bool:
    parts=token.split('.')
    return len(parts)==3 and all(re.fullmatch(r'[A-Za-z0-9_-]*',p or '') for p in parts)

def decode(token: str) -> dict:
    parts=token.split('.')
    if len(parts)!=3: raise ValueError('JWT must have three dot-separated parts.')
    out=[]
    for part in parts[:2]:
        part += '='*((4-len(part)%4)%4)
        out.append(json.loads(base64.urlsafe_b64decode(part).decode('utf-8')))
    return {'header':out[0],'payload':out[1],'signature_present':bool(parts[2]),'verified':False}

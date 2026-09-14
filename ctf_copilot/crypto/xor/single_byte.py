from __future__ import annotations
from ..scoring import quality

def candidates(hex_value: str, limit: int=10):
    data=bytes.fromhex(''.join(hex_value.split()))
    rows=[]
    for key in range(256):
        text=bytes(b^key for b in data).decode('latin1')
        rows.append((quality(text),key,text))
    return sorted(rows,reverse=True)[:limit]

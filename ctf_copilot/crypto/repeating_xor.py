"""Bounded repeating-key XOR recovery for hex ciphertexts."""
from __future__ import annotations
from .scoring import quality

def _distance(a: bytes,b: bytes) -> int: return sum((x^y).bit_count() for x,y in zip(a,b))

def crack(hex_value: str, max_key_size: int=16) -> list[tuple[float,bytes,str]]:
    try: data=bytes.fromhex(''.join(hex_value.split()))
    except ValueError: return []
    sizes=[]
    for size in range(2,min(max_key_size,len(data)//4)+1):
        blocks=[data[i:i+size] for i in range(0,size*4,size)]
        if len(blocks)<4 or any(len(x)!=size for x in blocks): continue
        score=sum(_distance(blocks[i],blocks[i+1])/size for i in range(3))/3
        sizes.append((score,size))
    rows=[]
    for _,size in sorted(sizes)[:4]:
        key=bytearray()
        for offset in range(size):
            column=data[offset::size]
            best=max((quality(bytes(x^k for x in column).decode('latin1')),k) for k in range(256))
            key.append(best[1])
        plain=bytes(x^key[i%size] for i,x in enumerate(data)).decode('latin1')
        rows.append((quality(plain),bytes(key),plain))
    return sorted(rows,reverse=True)[:5]

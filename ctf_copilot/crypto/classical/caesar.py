from __future__ import annotations
import codecs

def shift(value: str, amount: int) -> str:
    return ''.join(chr((ord(c)-97-amount)%26+97) if 'a'<=c<='z' else chr((ord(c)-65-amount)%26+65) if 'A'<=c<='Z' else c for c in value)

def all_shifts(value: str):
    for amount in range(1,26): yield amount, shift(value,amount)

def rot13(value: str) -> str: return codecs.decode(value,'rot_13')

def atbash(value: str) -> str:
    out=[]
    for c in value:
        if 'a'<=c<='z': out.append(chr(ord('z')-(ord(c)-ord('a'))))
        elif 'A'<=c<='Z': out.append(chr(ord('Z')-(ord(c)-ord('A'))))
        else: out.append(c)
    return ''.join(out)

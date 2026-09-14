from __future__ import annotations

import re

FLAG_PATTERNS = [
    re.compile(r"\b(?:flag|ctf|picoCTF|HTB|THM)\{[^{}\r\n]{1,300}\}", re.I),
    re.compile(r"\b[A-Za-z0-9_-]{2,24}\{[^{}\r\n]{1,300}\}"),
]


def find_flags(text: str) -> list[str]:
    out: list[str] = []
    for pattern in FLAG_PATTERNS:
        for match in pattern.findall(text):
            if match not in out:
                out.append(match)
    return out

def find_flags_bytes(data: bytes, max_xor_bytes: int = 65_536) -> list[str]:
    """Find flags in ordinary/wide text and small single-byte-XOR blobs."""
    out=[]
    for encoding in ('utf-8','utf-16le','utf-16be'):
        try: out.extend(find_flags(data.decode(encoding,'ignore')))
        except UnicodeError: pass
    if len(data)<=max_xor_bytes:
        for key in range(256):
            text=bytes(value^key for value in data).decode('latin1')
            found=find_flags(text)
            if found: out.extend(found)
    return list(dict.fromkeys(out))

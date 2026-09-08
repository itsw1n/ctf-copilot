from __future__ import annotations

import hashlib
import re
from pathlib import Path

FLAG_PATTERNS = [
    re.compile(r"\b(?:flag|ctf|picoCTF|HTB|THM)\{[^{}\r\n]{1,300}\}", re.I),
    re.compile(r"\b[A-Za-z0-9_-]{2,24}\{[^{}\r\n]{1,300}\}"),
]


def flags(text: str) -> list[str]:
    out: list[str] = []
    for pattern in FLAG_PATTERNS:
        for match in pattern.findall(text):
            if match not in out:
                out.append(match)
    return out


def strings(data: bytes, minlen: int = 4) -> list[str]:
    pattern = rb'[\x20-\x7e]{%d,}' % minlen
    return [m.decode('ascii', 'ignore') for m in re.findall(pattern, data)]


def sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def magic(head: bytes) -> str:
    signatures = [
        (b'\xff\xd8\xff', 'JPEG image'),
        (b'\x89PNG\r\n\x1a\n', 'PNG image'),
        (b'%PDF-', 'PDF document'),
        (b'PK\x03\x04', 'ZIP archive'),
        (b'\x7fELF', 'ELF executable'),
        (b'MZ', 'PE/Windows executable'),
    ]
    for signature, name in signatures:
        if head.startswith(signature):
            return name
    return 'Unknown / generic binary'

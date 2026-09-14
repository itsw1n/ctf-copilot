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

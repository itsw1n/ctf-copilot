from __future__ import annotations

import math
from ..scoring import quality


def decrypt(value: str, multiplier: int, shift: int) -> str:
    inverse = pow(multiplier, -1, 26)
    out = []
    for character in value:
        if character.isascii() and character.isalpha():
            base = 65 if character.isupper() else 97
            out.append(chr((inverse * (ord(character) - base - shift)) % 26 + base))
        else:
            out.append(character)
    return "".join(out)


def crack(value: str, limit: int = 8) -> list[tuple[float, int, int, str]]:
    rows = []
    for multiplier in range(1, 26):
        if math.gcd(multiplier, 26) != 1:
            continue
        for shift in range(26):
            text = decrypt(value, multiplier, shift)
            rows.append((quality(text), multiplier, shift, text))
    return sorted(rows, reverse=True)[:limit]

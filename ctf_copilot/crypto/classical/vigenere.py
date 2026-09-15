from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import string

from ..scoring import quality

FREQUENCIES = {
    letter: frequency for letter, frequency in zip(
        string.ascii_uppercase,
        (8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, .15, .77, 4.0,
         2.4, 6.7, 7.5, 1.9, .095, 6.0, 6.3, 9.1, 2.8, .98, 2.4, .15, 2.0, .074),
    )
}


@dataclass(frozen=True)
class VigenereCandidate:
    key: str
    plaintext: str
    score: float
    key_length_score: float


def decrypt(value: str, key: str) -> str:
    shifts = [ord(character.upper()) - 65 for character in key if character.isalpha()]
    if not shifts:
        raise ValueError("Vigenere key must contain letters.")
    out = []
    index = 0
    for character in value:
        if character.isalpha() and character.isascii():
            base = 65 if character.isupper() else 97
            out.append(chr((ord(character) - base - shifts[index % len(shifts)]) % 26 + base))
            index += 1
        else:
            out.append(character)
    return "".join(out)


def _ic(text: str) -> float:
    letters = [character for character in text.upper() if character in string.ascii_uppercase]
    length = len(letters)
    if length < 2:
        return 0.0
    counts = Counter(letters)
    return sum(count * (count - 1) for count in counts.values()) / (length * (length - 1))


def estimate_key_lengths(value: str, maximum: int = 20) -> list[tuple[float, int]]:
    letters = "".join(character for character in value.upper() if character in string.ascii_uppercase)
    rows = []
    for size in range(2, min(maximum, max(2, len(letters) // 4)) + 1):
        columns = [letters[offset::size] for offset in range(size)]
        score = sum(_ic(column) for column in columns) / size
        rows.append((score, size))
    return sorted(rows, reverse=True)[:6]


def _best_shift(column: str) -> int:
    if not column:
        return 0
    best = (float("inf"), 0)
    for shift in range(26):
        decoded = [chr((ord(character) - 65 - shift) % 26 + 65) for character in column]
        counts = Counter(decoded)
        total = len(decoded)
        chi = 0.0
        for letter in string.ascii_uppercase:
            expected = FREQUENCIES[letter] * total / 100
            chi += (counts[letter] - expected) ** 2 / max(expected, 0.001)
        best = min(best, (chi, shift))
    return best[1]


def crack(value: str, max_key_length: int = 20) -> list[VigenereCandidate]:
    letters = "".join(character for character in value.upper() if character in string.ascii_uppercase)
    if len(letters) < 24:
        return []
    rows = []
    for ic_score, size in estimate_key_lengths(value, max_key_length):
        key = "".join(chr(_best_shift(letters[offset::size]) + 65) for offset in range(size))
        plaintext = decrypt(value, key)
        rows.append(VigenereCandidate(key, plaintext, quality(plaintext), ic_score))
    return sorted(rows, key=lambda row: row.score, reverse=True)[:5]

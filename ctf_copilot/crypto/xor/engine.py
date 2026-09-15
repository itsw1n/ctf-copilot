from __future__ import annotations

from dataclasses import dataclass

from ..normalization import parse_bytes, readable
from ..scoring import has_known_flag, quality
from .single_byte import candidates as single_candidates
from ..repeating_xor import crack as repeating_candidates


@dataclass(frozen=True)
class XorResult:
    technique: str
    plaintext: str
    key: bytes = b""
    offset: int = 0
    score: float = 0.0
    evidence: str = ""


def single(value: str, fmt: str = "auto", limit: int = 10) -> list[XorResult]:
    data = parse_bytes(value, fmt)
    rows = single_candidates(data.hex(), limit)
    return [XorResult("single-byte XOR", text, bytes([key]), 0, score, "tested all 256 one-byte keys") for score, key, text in rows]


def repeating(value: str, fmt: str = "auto", max_key_size: int = 40) -> list[XorResult]:
    data = parse_bytes(value, fmt)
    return [XorResult("repeating-key XOR", text, key, 0, score, "normalized Hamming-distance key-size estimate") for score, key, text in repeating_candidates(data.hex(), max_key_size)]


def xor_values(first: str, second: str, first_format: str = "auto", second_format: str = "auto") -> bytes:
    left, right = parse_bytes(first, first_format), parse_bytes(second, second_format)
    return bytes(a ^ b for a, b in zip(left, right))


def known_plaintext(ciphertext: str, crib: str, fmt: str = "auto", max_offsets: int = 256) -> list[XorResult]:
    data, known = parse_bytes(ciphertext, fmt), crib.encode()
    if not known or len(known) > len(data):
        return []
    rows = []
    for offset in range(min(len(data) - len(known) + 1, max_offsets)):
        key = bytes(data[offset + index] ^ value for index, value in enumerate(known))
        repeated = bytes(value ^ key[index % len(key)] for index, value in enumerate(data))
        text = readable(repeated) or repeated.decode("latin1")
        score = quality(text) + (4 if has_known_flag(text) else 0)
        rows.append(XorResult("known-plaintext XOR", text, key, offset, score, f"crib tested at offset {offset}"))
    return sorted(rows, key=lambda row: row.score, reverse=True)[:10]


def crib_drag(first: str, second: str, crib: str, fmt: str = "auto", max_offsets: int = 256) -> list[XorResult]:
    combined = xor_values(first, second, fmt, fmt)
    known = crib.encode()
    rows = []
    for offset in range(min(max(0, len(combined) - len(known) + 1), max_offsets)):
        other = bytes(combined[offset + index] ^ value for index, value in enumerate(known))
        text = readable(other) or other.decode("latin1")
        rows.append(XorResult("crib dragging", text, known, offset, quality(text), "two ciphertexts XOR to two plaintexts when a keystream is reused"))
    return sorted(rows, key=lambda row: row.score, reverse=True)[:10]

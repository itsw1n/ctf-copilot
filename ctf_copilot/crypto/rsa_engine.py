"""Bounded, deterministic RSA weakness analysis for CTF-supplied parameters."""
from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
import math
from pathlib import Path
import re
from typing import Iterable

from .normalization import readable
from ..shared.flags import find_flags

PARAMETER = re.compile(r"(?im)^\s*(n|e|c|p|q|d)(?:[_-]?(\d+))?\s*[:=]\s*(0x[0-9a-f]+|\d+)")


@dataclass
class RSARecord:
    values: dict[str, int]
    source: str = "input"


@dataclass
class RSAResult:
    technique: str
    evidence: str
    plaintext: bytes | None = None
    details: str = ""
    verified: bool = False


def _source_text(value: str) -> tuple[str, str]:
    path = Path(value)
    if path.is_file():
        return path.read_text(errors="replace"), str(path)
    return value, "literal"


def parse_records(values: str | Iterable[str]) -> list[RSARecord]:
    sources = [values] if isinstance(values, str) else list(values)
    records = []
    for source in sources:
        text, label = _source_text(source)
        grouped: dict[str, dict[str, int]] = {}
        for name, suffix, raw in PARAMETER.findall(text):
            grouped.setdefault(suffix or "0", {})[name.lower()] = int(raw, 0)
        records.extend(RSARecord(row, f"{label}#{group}") for group, row in grouped.items() if row)
        if "-----BEGIN" in text and "PUBLIC KEY-----" in text:
            try:
                from Crypto.PublicKey import RSA
                key = RSA.import_key(text.encode())
                records.append(RSARecord({"n": int(key.n), "e": int(key.e)}, label + "#pem"))
            except (ImportError, ValueError, IndexError):
                pass
    return records


def integer_root(value: int, exponent: int) -> tuple[int, bool]:
    if value < 0 or exponent < 1:
        return 0, False
    if value in (0, 1) or exponent == 1:
        return value, True
    low = 0
    high = 1 << ((value.bit_length() + exponent - 1) // exponent + 1)
    while low + 1 < high:
        middle = (low + high) // 2
        powered = middle ** exponent
        if powered <= value:
            low = middle
        else:
            high = middle
    return low, low ** exponent == value


def int_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _trial_factor(number: int, limit: int = 1_000_000) -> tuple[int, int] | None:
    if number % 2 == 0:
        return 2, number // 2
    top = min(math.isqrt(number), limit)
    for divisor in range(3, top + 1, 2):
        if number % divisor == 0:
            return divisor, number // divisor
    return None


def _decrypt(record: RSARecord, p: int, q: int) -> RSAResult | None:
    values = record.values
    if not all(key in values for key in ("e", "c")):
        return None
    phi = (p - 1) * (q - 1)
    try:
        d = pow(values["e"], -1, phi)
    except ValueError:
        return RSAResult("factor recovery", f"p={p}, q={q}", details="e has no inverse modulo phi")
    message = pow(values["c"], d, p * q)
    plaintext = int_bytes(message)
    verified = pow(message, values["e"], p * q) == values["c"] % (p * q)
    return RSAResult("RSA private-key recovery", f"n factors as {p} × {q}", plaintext, f"d={d}", verified)


def _continued_fraction(numerator: int, denominator: int) -> list[int]:
    rows = []
    while denominator:
        value, remainder = divmod(numerator, denominator)
        rows.append(value)
        numerator, denominator = denominator, remainder
    return rows


def _convergents(parts: list[int]):
    p0, p1, q0, q1 = 0, 1, 1, 0
    for part in parts:
        p0, p1 = p1, part * p1 + p0
        q0, q1 = q1, part * q1 + q0
        yield p1, q1


def _wiener(record: RSARecord) -> RSAResult | None:
    values = record.values
    if not all(key in values for key in ("n", "e", "c")):
        return None
    n, e = values["n"], values["e"]
    for k, d in _convergents(_continued_fraction(e, n)):
        if not k or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        total = n - phi + 1
        discriminant = total * total - 4 * n
        if discriminant < 0:
            continue
        root = math.isqrt(discriminant)
        if root * root == discriminant and (total + root) % 2 == 0:
            message = pow(values["c"], d, n)
            plaintext = int_bytes(message)
            return RSAResult("Wiener small-d attack", f"continued fractions recovered d={d}", plaintext, verified=pow(message, e, n) == values["c"] % n)
    return None


def _pow_signed(value: int, exponent: int, modulus: int) -> int:
    if exponent < 0:
        value = pow(value, -1, modulus)
        exponent = -exponent
    return pow(value, exponent, modulus)


def _egcd(left: int, right: int) -> tuple[int, int, int]:
    if right == 0:
        return left, 1, 0
    gcd, x1, y1 = _egcd(right, left % right)
    return gcd, y1, x1 - (left // right) * y1


def _crt(items: list[tuple[int, int]]) -> tuple[int, int] | None:
    modulus = math.prod(n for _, n in items)
    total = 0
    for residue, n in items:
        partial = modulus // n
        try:
            inverse = pow(partial, -1, n)
        except ValueError:
            return None
        total += residue * partial * inverse
    return total % modulus, modulus


def analyze_rsa(values: str | Iterable[str], max_k: int = 100_000, factor_limit: int = 1_000_000) -> list[RSAResult]:
    records = parse_records(values)
    results: list[RSAResult] = []
    for record in records:
        row = record.values
        if all(key in row for key in ("p", "q", "e", "c")):
            result = _decrypt(record, row["p"], row["q"])
            if result:
                result.technique = "supplied p and q"
                results.append(result)
        if all(key in row for key in ("n", "e", "c")):
            n, e, c = row["n"], row["e"], row["c"]
            if 1 < e <= 17:
                root, exact = integer_root(c, e)
                if exact:
                    results.append(RSAResult("textbook low exponent", "ciphertext is an exact e-th power", int_bytes(root), verified=pow(root, e) == c))
                else:
                    for k in range(1, max_k + 1):
                        root, exact = integer_root(c + k * n, e)
                        if exact:
                            results.append(RSAResult("bounded c + k*n low-e", f"c + {k}×n is an exact e-th power", int_bytes(root), verified=pow(root, e, n) == c % n))
                            break
            wiener = _wiener(record)
            if wiener:
                results.append(wiener)
            factors = _trial_factor(n, factor_limit)
            if factors:
                result = _decrypt(record, *factors)
                if result:
                    result.technique = "bounded factorization"
                    results.append(result)

    for first, second in combinations(records, 2):
        left, right = first.values, second.values
        if "n" in left and "n" in right and left["n"] != right["n"]:
            shared = math.gcd(left["n"], right["n"])
            if 1 < shared < left["n"]:
                for record in (first, second):
                    result = _decrypt(record, shared, record.values["n"] // shared)
                    if result:
                        result.technique = "shared-prime GCD"
                        result.evidence = f"gcd of two moduli revealed p={shared}"
                        results.append(result)
        if left.get("n") == right.get("n") and all(key in left for key in ("e", "c")) and all(key in right for key in ("e", "c")):
            gcd, a, b = _egcd(left["e"], right["e"])
            if gcd == 1:
                try:
                    message = (_pow_signed(left["c"], a, left["n"]) * _pow_signed(right["c"], b, left["n"])) % left["n"]
                    results.append(RSAResult("common-modulus attack", "same modulus and coprime public exponents", int_bytes(message), verified=True))
                except ValueError:
                    pass

    by_exponent: dict[int, list[RSARecord]] = {}
    for record in records:
        if all(key in record.values for key in ("n", "e", "c")):
            by_exponent.setdefault(record.values["e"], []).append(record)
    for exponent, group in by_exponent.items():
        if 2 <= exponent <= 7 and len(group) >= exponent:
            for chosen in combinations(group[:10], exponent):
                if any(math.gcd(a.values["n"], b.values["n"]) != 1 for a, b in combinations(chosen, 2)):
                    continue
                combined = _crt([(row.values["c"], row.values["n"]) for row in chosen])
                if combined:
                    root, exact = integer_root(combined[0], exponent)
                    if exact:
                        results.append(RSAResult("Håstad broadcast attack", f"{exponent} pairwise-coprime ciphertexts share e={exponent}", int_bytes(root), verified=True))
                        break

    unique = []
    seen = set()
    for result in results:
        identity = (result.technique, result.plaintext, result.evidence)
        if identity not in seen:
            seen.add(identity)
            unique.append(result)
    return unique


def render_rsa(values: str | Iterable[str], max_k: int = 100_000) -> str:
    records = parse_records(values)
    if not records:
        return "RSA analysis needs named values such as n=..., e=..., c=... or a PEM public key."
    lines = ["RSA ANALYSIS", "============", f"Parameter sets: {len(records)}"]
    results = analyze_rsa(values, max_k=max_k)
    if not results:
        largest = max((row.values.get("n", 0).bit_length() for row in records), default=0)
        lines += ["", "No supported bounded weakness succeeded.", f"Largest modulus: {largest} bits.", "Meaning: a normal large RSA modulus is not reasonably factorable by this local helper.", "Next: look for reused primes, multiple ciphertexts, leaked p/q, a small exponent, or an oracle clue."]
        return "\n".join(lines)
    for index, result in enumerate(results, 1):
        lines += ["", f"[{index}] {result.technique}", f"Evidence: {result.evidence}"]
        if result.details:
            lines.append(f"Details: {result.details}")
        if result.plaintext is not None:
            text = readable(result.plaintext)
            lines.append(f"Plaintext bytes: {result.plaintext!r}")
            if text is not None:
                lines.append(f"Recovered plaintext text: {text}")
                flags = find_flags(text)
                if flags:
                    lines.extend(["Validated flag candidates:"] + [f"  {flag}" for flag in flags])
        lines.append(f"Verification: {'passed' if result.verified else 'not available'}")
    return "\n".join(lines)

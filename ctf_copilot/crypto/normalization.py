from __future__ import annotations

from dataclasses import dataclass
import base64
from pathlib import Path
import re


@dataclass(frozen=True)
class CryptoValue:
    raw: bytes
    text: str | None
    representation: str
    source: str = "input"


def load_value(value: str) -> CryptoValue:
    """Load an existing file, or treat the argument as literal challenge data."""
    if value.startswith("text:"):
        text = value[5:]
        return CryptoValue(text.encode(), text, "text", "literal")
    path = Path(value)
    if path.is_file():
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        return CryptoValue(raw, text, "file", str(path))
    text = value.strip()
    match = re.fullmatch(r"b(['\"])(.*)\1", text, re.S)
    if match:
        text = match.group(2)
    return CryptoValue(text.encode(), text, "text", "literal")


def parse_bytes(value: str | bytes, fmt: str = "auto") -> bytes:
    if isinstance(value, bytes):
        return value
    raw = value.strip()
    if fmt == "raw":
        return raw.encode()
    compact = re.sub(r"\s+", "", raw)
    hexed = re.sub(r"(?i)0x|[\s,:]", "", raw)
    if fmt == "hex":
        return bytes.fromhex(hexed)
    if fmt in {"decimal", "integer"} or (fmt == "auto" and re.fullmatch(r"\d+", raw)):
        number = int(raw, 10)
        return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
    if fmt == "auto" and len(hexed) >= 2 and len(hexed) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", hexed):
        has_hex_evidence = bool(re.search(r"(?i)0x", raw) or re.search(r"[a-fA-F]", hexed) or re.search(r"[\s,:]", raw))
        if has_hex_evidence:
            return bytes.fromhex(hexed)
    if fmt == "base64" or (fmt == "auto" and len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact)):
        candidate = compact.replace("-", "+").replace("_", "/")
        candidate += "=" * ((4 - len(candidate) % 4) % 4)
        try:
            return base64.b64decode(candidate, validate=True)
        except ValueError:
            if fmt == "base64":
                raise
    if fmt == "binary" or (fmt == "auto" and len(compact) >= 8 and len(compact) % 8 == 0 and re.fullmatch(r"[01]+", compact)):
        return bytes(int(compact[index:index + 8], 2) for index in range(0, len(compact), 8))
    decimal = re.fullmatch(r"[\[\(]?\s*(\d{1,3}(?:\s*[, ]\s*\d{1,3})+)\s*[\]\)]?", raw)
    if decimal:
        values = [int(item) for item in re.findall(r"\d+", raw)]
        if all(0 <= item <= 255 for item in values):
            return bytes(values)
    return raw.encode()


def readable(raw: bytes) -> str | None:
    for encoding in ("utf-8", "utf-16le", "utf-16be"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
        if text and printable / len(text) >= 0.85:
            return text
    return None

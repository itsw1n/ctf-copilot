from __future__ import annotations

import re

FLAG_PATTERNS = [
    re.compile(r"\b(?:flag|ctf|picoCTF|HTB|THM)\{[^{}\r\n]{1,300}\}", re.I),
    re.compile(r"\b[A-Za-z0-9_-]{2,24}\{[^{}\r\n]{1,300}\}"),
]

PLACEHOLDER_CONTENT = re.compile(
    r"(?i)^(?:\.{2,}|flag(?:[_ -]?(?:here|goes here))?|redacted|example|placeholder|xxx+|your[_ -]?flag)$"
)


def is_placeholder_flag(value: str) -> bool:
    if "{" not in value or not value.endswith("}"):
        return True
    content = value[value.find("{") + 1:-1].strip()
    return not content or bool(PLACEHOLDER_CONTENT.fullmatch(content))


def find_flags(text: str) -> list[str]:
    out: list[str] = []
    for pattern in FLAG_PATTERNS:
        for match in pattern.findall(text):
            if match not in out and not is_placeholder_flag(match):
                out.append(match)
    return out


def validate_flags(text: str, pattern: str | None = None, source_kind: str = "derived") -> tuple[list[str], list[str]]:
    """Return (validated, candidates), keeping source literals conservative."""
    rows = find_flags(text)
    custom = re.compile(pattern) if pattern else None
    confirmed: list[str] = []
    candidates: list[str] = []
    for value in rows:
        if custom and custom.fullmatch(value):
            confirmed.append(value)
        elif source_kind in {"decoded", "decrypted", "extracted", "response", "direct"} and re.match(
            r"(?i)^(?:flag|picoCTF|HTB|THM)\{", value
        ):
            confirmed.append(value)
        else:
            candidates.append(value)
    return list(dict.fromkeys(confirmed)), list(dict.fromkeys(candidates))

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

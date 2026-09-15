from __future__ import annotations

import re


def identify(value: str) -> list[tuple[str, str]]:
    text = value.strip()
    rows = []
    if re.fullmatch(r"[0-9a-fA-F]{32}", text):
        rows.append(("MD5 or NTLM", "32 hexadecimal characters; context distinguishes them"))
    if re.fullmatch(r"[0-9a-fA-F]{40}", text):
        rows.append(("SHA-1", "40 hexadecimal characters"))
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        rows.append(("SHA-256", "64 hexadecimal characters"))
    if re.fullmatch(r"[0-9a-fA-F]{128}", text):
        rows.append(("SHA-512", "128 hexadecimal characters"))
    if text.startswith(("$2a$", "$2b$", "$2y$")):
        rows.append(("bcrypt", "bcrypt modular-crypt prefix"))
    if text.startswith("$argon2"):
        rows.append(("Argon2", "Argon2 encoded-hash prefix"))
    return rows


def render(value: str) -> str:
    rows = identify(value)
    if not rows:
        return "No common hash format recognized. Hash type cannot always be determined from digest text alone."
    lines = ["LIKELY HASH FAMILY", "=================="]
    for name, reason in rows:
        lines += [f"- {name}", f"  Evidence: {reason}"]
    lines += ["", "Meaning: hashes are tested against plausible guesses; they are not directly decoded.", "Next: use John/Hashcat only when challenge evidence suggests a guessable plaintext."]
    return "\n".join(lines)

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .normalization import parse_bytes, readable
from ..shared.flags import find_flags

try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import pad, unpad
except ImportError:  # pragma: no cover - PyCryptodome is optional at import time
    AES = DES = DES3 = None  # type: ignore[assignment]
    pad = unpad = None  # type: ignore[assignment]


@dataclass(frozen=True)
class BlockResult:
    algorithm: str
    mode: str
    plaintext: bytes
    unpadded: bool
    verified: bool


def repeated_blocks(value: str | bytes, block_size: int = 16, fmt: str = "auto") -> tuple[int, int]:
    data = parse_bytes(value, fmt)
    blocks = [data[index:index + block_size] for index in range(0, len(data), block_size) if len(data[index:index + block_size]) == block_size]
    return len(blocks), len(blocks) - len(set(blocks))


def decrypt(ciphertext: str, algorithm: str, mode: str, key: str,
            iv: str | None = None, nonce: str | None = None,
            input_format: str = "auto", key_format: str = "auto") -> BlockResult:
    if AES is None or DES is None or DES3 is None or unpad is None or pad is None:
        raise RuntimeError("PyCryptodome is required for block-cipher decryption.")
    algorithms: dict[str, Any] = {"aes": AES, "des": DES, "3des": DES3}
    if algorithm not in algorithms:
        raise ValueError("algorithm must be aes, des, or 3des")
    module = algorithms[algorithm]
    modes = {"ecb": module.MODE_ECB, "cbc": module.MODE_CBC, "ctr": module.MODE_CTR}
    if mode not in modes:
        raise ValueError("mode must be ecb, cbc, or ctr")
    raw, key_bytes = parse_bytes(ciphertext, input_format), parse_bytes(key, key_format)
    if algorithm == "aes" and len(key_bytes) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if algorithm == "des" and len(key_bytes) != 8:
        raise ValueError("DES key must be 8 bytes")
    if algorithm == "3des" and len(key_bytes) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes")
    kwargs: dict[str, bytes] = {}
    if mode == "cbc":
        if iv is None:
            raise ValueError("CBC mode requires --iv")
        kwargs["iv"] = parse_bytes(iv, "auto")
        if len(kwargs["iv"]) != module.block_size:
            raise ValueError(f"{algorithm.upper()} CBC IV must be {module.block_size} bytes")
    elif mode == "ctr":
        if nonce is None:
            raise ValueError("CTR mode requires --nonce")
        kwargs["nonce"] = parse_bytes(nonce, "auto")
    cipher = module.new(key_bytes, modes[mode], **kwargs)
    plaintext = cipher.decrypt(raw)
    unpadded = False
    if mode in {"ecb", "cbc"}:
        try:
            plaintext = unpad(plaintext, module.block_size)
            unpadded = True
        except ValueError:
            pass
    check = module.new(key_bytes, modes[mode], **kwargs).encrypt(
        plaintext if mode == "ctr" else (pad(plaintext, module.block_size) if unpadded else plaintext)
    )
    return BlockResult(algorithm, mode, plaintext, unpadded, check == raw)


def render(ciphertext: str, algorithm: str = "aes", mode: str = "ecb", key: str | None = None,
           iv: str | None = None, nonce: str | None = None,
           input_format: str = "auto", key_format: str = "auto") -> str:
    block_size = 8 if algorithm in {"des", "3des"} else 16
    count, repeats = repeated_blocks(ciphertext, block_size, input_format)
    lines = ["BLOCK-CIPHER ANALYSIS", "=====================", f"Algorithm: {algorithm.upper()}", f"Mode: {mode.upper()}", f"Complete blocks: {count}", f"Repeated blocks: {repeats}"]
    if repeats:
        lines += ["Finding: repeated ciphertext blocks detected.", "Meaning: this strongly supports ECB when equal plaintext blocks produce equal ciphertext blocks."]
    if key is None:
        lines += ["", "No key supplied; decryption was not attempted.", "Next: provide an explicitly supplied/recovered key with `ctf crypto block ... --key ...`."]
        return "\n".join(lines)
    result = decrypt(ciphertext, algorithm, mode, key, iv, nonce, input_format, key_format)
    text = readable(result.plaintext)
    lines += ["", f"PKCS#7 padding removed: {'yes' if result.unpadded else 'no/invalid'}", f"Re-encryption verification: {'passed' if result.verified else 'failed'}", f"Plaintext bytes: {result.plaintext!r}"]
    if text is not None:
        lines.append(f"Plaintext text: {text}")
        flags = find_flags(text)
        if flags:
            lines.extend(["Validated flag candidates:"] + [f"  {flag}" for flag in flags])
    return "\n".join(lines)

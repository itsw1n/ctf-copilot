"""Generate a reviewed, editable solve-script scaffold from Python crypto source."""
from __future__ import annotations
from pathlib import Path
from .inspect import inspect_python

TEMPLATE='''#!/usr/bin/env python3
"""CTF Copilot generated starting point. Review every assumption before use."""
# Source inspected: {source}
# This file intentionally does not execute the supplied challenge source.

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))

def main() -> None:
    # Copy only known ciphertext/key/constants from the challenge here.
    # Reverse the encryption operations in reverse order.
    # Example: plaintext = xor_bytes(ciphertext, key)
    raise SystemExit("Edit this scaffold using the evidence comments above.")

if __name__ == "__main__":
    main()
'''

def generate(source: str, output: str | None = None) -> str:
    p=Path(source)
    if not p.is_file(): return f'Not a file: {p}'
    destination=Path(output) if output else p.with_name('solve_generated.py')
    if destination.exists(): return f'Refusing to overwrite existing file: {destination}'
    destination.write_text(TEMPLATE.format(source=p),encoding='utf-8')
    return inspect_python(str(p))+'\n\nGenerated editable scaffold: '+str(destination)+'\nReview the original algorithm and fill in only verified constants.'

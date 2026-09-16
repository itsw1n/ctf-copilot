"""Compatibility wrapper: delegates to shared/flags.py (single source of truth)."""
from __future__ import annotations

from pathlib import Path

from ..shared.flags import find_flags as _shared_find


def find(text, prefix=None):
    extra = [prefix] if prefix else None
    return _shared_find(text or "", extra_prefixes=extra)


def scan(value, prefix=None):
    p = Path(value)
    results = []
    if p.is_dir():
        for f in p.rglob('*'):
            if f.is_file() and f.stat().st_size <= 10_000_000:
                try:
                    text = f.read_text(errors='ignore')
                    for flag in find(text, prefix):
                        results.append((str(f), flag))
                except OSError:
                    pass
    elif p.is_file():
        for flag in find(p.read_text(errors='ignore'), prefix):
            results.append((str(p), flag))
    else:
        for flag in find(value, prefix):
            results.append(('<text>', flag))
    return results

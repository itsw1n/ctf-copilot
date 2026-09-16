"""Compatibility wrapper: delegates to shared/flags.py (single source of truth)."""
from __future__ import annotations

from ..shared.flags import get_flag_patterns


def patterns(prefix=None):
    extra = [prefix] if prefix else None
    return get_flag_patterns(extra_prefixes=extra)

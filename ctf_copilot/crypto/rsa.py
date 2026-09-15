"""Compatibility facade for the extensible RSA analysis engine."""
from .rsa_engine import analyze_rsa, integer_root, parse_records, render_rsa


def solve(text: str) -> str:
    return render_rsa(text)


__all__ = ["analyze_rsa", "integer_root", "parse_records", "render_rsa", "solve"]

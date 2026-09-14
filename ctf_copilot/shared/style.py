from __future__ import annotations
import os
import sys

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
YELLOW = "\x1b[33m"
GREEN = "\x1b[32m"
CYAN = "\x1b[36m"

def supports_color(no_color_flag: bool = False) -> bool:
    try:
        if no_color_flag:
            return False
        if os.environ.get("NO_COLOR"):
            return False
        return sys.stdout.isatty()
    except Exception:
        return False

def c(text: str, *codes: str, enabled: bool) -> str:
    if not enabled or not codes:
        return text
    return f"{''.join(codes)}{text}{RESET}"

def header(text: str, enabled: bool) -> str:
    return c(text, BOLD, YELLOW, enabled=enabled)

def section(text: str, enabled: bool) -> str:
    return c(text, BOLD, CYAN, enabled=enabled)

def cmd(text: str, enabled: bool) -> str:
    return c(text, BOLD, GREEN, enabled=enabled)

def dim(text: str, enabled: bool) -> str:
    return c(text, DIM, enabled=enabled)

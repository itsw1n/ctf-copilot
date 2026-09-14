from __future__ import annotations
import re

PATTERNS = [
    re.compile(r'''["']((?:/api/|/graphql|/admin|/debug|/internal|/v\d+/)[A-Za-z0-9_./?=&%:#@+\-{}:]*)["']''', re.I),
    re.compile(r'''fetch\(\s*["']([^"']+)["']''', re.I),
    re.compile(r'''axios\.(?:get|post|put|patch|delete)\(\s*["']([^"']+)["']''', re.I),
]

def extract(text: str):
    out=[]
    for p in PATTERNS:
        out.extend(p.findall(text))
    return list(dict.fromkeys(out))

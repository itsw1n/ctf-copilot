"""Offline static source triage. It never starts a local application."""
from __future__ import annotations
from pathlib import Path
import re

RULES = [
    (r'\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*(?:\+|f["\']|\.format\()', 'SQL query assembled from input', 'Inspect this route for SQL injection.'),
    (r'\b(?:os\.system|subprocess\.|exec\(|eval\()', 'command/code execution sink', 'Trace whether request input reaches this call.'),
    (r'\b(?:render_template_string|Template\(|jinja)', 'template rendering', 'Trace user-controlled values for SSTI.'),
    (r'\b(?:send_file|send_from_directory|open\()', 'file access sink', 'Check path normalization and traversal controls.'),
    (r'(?i)(?:secret|api[_-]?key|password|token)\s*[:=]\s*["\']', 'hard-coded secret-looking value', 'Verify context; it may unlock another artifact.'),
    (r'\b(?:is_admin|role|authorize|permission)\b', 'authorization-related logic', 'Review access checks around privileged routes.'),
]
ROUTES=re.compile(r'(?:@\w+\.route\(\s*["\']([^"\']+)|(?:app|router)\.(?:get|post|put|delete)\(\s*["\']([^"\']+))',re.I)

def inspect(path: str) -> str:
    root=Path(path)
    if not root.exists(): return f'Not found: {root}'
    files=[root] if root.is_file() else [p for p in root.rglob('*') if p.suffix.lower() in {'.py','.js','.ts','.php','.go','.java','.rb'}]
    out=['WEB SOURCE TRIAGE (static; nothing executed)','===============================================']
    hits=[]; routes=[]
    for file in files[:500]:
        if file.stat().st_size>1_000_000: continue
        text=file.read_text(errors='replace')
        for match in ROUTES.finditer(text): routes.append((file,match.group(1) or match.group(2)))
        for pattern,label,next_step in RULES:
            for line_no,line in enumerate(text.splitlines(),1):
                if re.search(pattern,line,re.I): hits.append((file,line_no,label,next_step,line.strip()[:180]))
    if routes: out += ['', 'Routes:']+[f'  {f}: {route}' for f,route in routes[:100]]
    if hits:
        out += ['', 'Evidence-triggered review points:']
        for f,line,label,next_step,source in hits[:150]: out += [f'  {f}:{line} — {label}',f'    {source}',f'    Next: {next_step}']
    if not routes and not hits: out.append('No supported source patterns found. Inspect framework configuration and templates manually.')
    return '\n'.join(out)

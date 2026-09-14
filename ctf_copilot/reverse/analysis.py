from __future__ import annotations
from . import symbols
from ..shared.tooling import run_tool, which

INTERESTING=('main','win','flag','check','verify','password','secret','decrypt','decode','auth','login')
IMPORTS=('strcmp','strncmp','memcmp','gets','fgets','scanf','strcpy','strncpy','printf','puts','system','execve','read','write','malloc','free')

def functions(path: str) -> str:
    if not which('readelf'): return 'readelf is not installed.'
    text=run_tool(['readelf','-Ws',path],timeout=30,max_output=120000)[1]
    rows=[]
    for line in text.splitlines():
        low=line.lower()
        if ' func ' in f' {low} ' and any(k in low for k in INTERESTING): rows.append(line.strip())
    return 'INTERESTING FUNCTIONS\n=====================\n'+('\n'.join(rows[:120]) if rows else 'No obvious named high-signal functions found (binary may be stripped).')

def imports(path: str) -> str:
    if not which('readelf'): return 'readelf is not installed.'
    text=run_tool(['readelf','-Ws',path],timeout=30,max_output=120000)[1]
    rows=[]
    for line in text.splitlines():
        if ' UND ' in f' {line} ' and any(k in line.lower() for k in IMPORTS): rows.append(line.strip())
    hints=[]
    joined=' '.join(rows).lower()
    if any(x in joined for x in ('strcmp','strncmp','memcmp')): hints.append('comparison imports found -> inspect their call sites for password/key checks')
    if any(x in joined for x in ('gets','strcpy','scanf')): hints.append('unsafe/input functions found -> also run `ctf pwn triage`')
    if 'system' in joined: hints.append('system() imported -> inspect whether user-controlled data can reach it')
    out=['INTERESTING IMPORTS','===================']+(rows[:120] or ['No obvious high-signal imports found.'])
    if hints: out += ['','NEXT CLUES']+[f'  - {h}' for h in hints]
    return '\n'.join(out)

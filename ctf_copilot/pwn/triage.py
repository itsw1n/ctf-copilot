from __future__ import annotations
import re
from pathlib import Path
from ..shared.tooling import run_tool, which

DANGEROUS=('gets','strcpy','strcat','scanf','printf','system','execve','read')

def triage(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    out=['PWN TRIAGE','==========']
    check=''
    if which('checksec'):
        check=run_tool(['checksec','--file='+str(p)],timeout=30,max_output=40000)[1]
        out += ['','[protections]',check]
    imports=''
    if which('readelf'):
        raw=run_tool(['readelf','-Ws',str(p)],timeout=30,max_output=100000)[1]
        rows=[x.strip() for x in raw.splitlines() if ' UND ' in f' {x} ' and any(k in x.lower() for k in DANGEROUS)]
        imports='\n'.join(rows)
        out += ['','[interesting imports]',imports or '(none found)']
    hints=[]
    low=(check+' '+imports).lower()
    if any(k in low for k in ('gets','strcpy','scanf')): hints.append('Unsafe/input function found: inspect for stack/heap overflow paths.')
    if 'printf' in low: hints.append('printf imported: inspect whether user input is ever used as the format string.')
    if 'system' in low or 'execve' in low: hints.append('Command-execution function imported: inspect whether controlled input reaches it.')
    if 'no canary found' in low or 'canary' in low and 'disabled' in low: hints.append('No stack canary may make a stack overwrite easier to exploit.')
    if 'no pie' in low or 'pie' in low and 'disabled' in low: hints.append('No PIE means code addresses are typically stable between runs.')
    if not hints: hints.append('No obvious exploitation direction from quick static triage; inspect code/behavior in GDB.')
    out += ['','LIKELY NEXT DIRECTIONS']+[f'  - {h}' for h in hints]
    out += ['','Useful next commands:','  ctf pwn cyclic create 200','  ctf reverse imports <binary>','  ctf reverse disasm <binary> --function <name>','  ctf pwn rop <binary>']
    return '\n'.join(out)

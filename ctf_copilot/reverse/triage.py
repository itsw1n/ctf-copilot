from pathlib import Path
from ..shared.tooling import run_tool, which
def triage(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    out=['BINARY TRIAGE','=============']; keywords=('gets','strcpy','strcat','scanf','printf','system','execve','win','flag','secret','password')
    for label,argv in [('file',['file',str(p)]),('checksec',['checksec','--file='+str(p)]),('ELF header',['readelf','-h',str(p)]),('symbols',['readelf','-Ws',str(p)]),('strings',['strings','-a','-n','4',str(p)])]:
        if not which(argv[0]): continue
        _,text=run_tool(argv,timeout=30,max_output=60000)
        if label in ('symbols','strings'): text='\n'.join(x for x in text.splitlines() if any(k in x.lower() for k in keywords)) or '(no high-signal matches)'
        out += ['',f'[{label}]',text]
    return '\n'.join(out)

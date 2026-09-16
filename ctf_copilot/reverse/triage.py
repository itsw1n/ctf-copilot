from pathlib import Path
from ..shared.flags import find_flags
from ..shared.tooling import run_tool, which
def triage(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    out=['BINARY TRIAGE','=============']; keywords=('gets','strcpy','strcat','scanf','printf','system','execve','win','flag','secret','password')
    seen=''
    for label,argv in [('file',['file',str(p)]),('checksec',['checksec','--file='+str(p)]),('ELF header',['readelf','-h',str(p)]),('symbols',['readelf','-Ws',str(p)]),('strings',['strings','-a','-n','4',str(p)])]:
        if not which(argv[0]): continue
        _,text=run_tool(argv,timeout=30,max_output=60000)
        seen+= '\n' + text
        if label in ('symbols','strings'): text='\n'.join(x for x in text.splitlines() if any(k in x.lower() for k in keywords)) or '(no high-signal matches)'
        out += ['',f'[{label}]',text]
    flags=find_flags(seen)
    if flags: out += ['','Flag-like strings (unconfirmed):'] + [f'  {f}' for f in flags[:20]]
    return '\n'.join(out)

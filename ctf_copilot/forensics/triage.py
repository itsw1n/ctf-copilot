from pathlib import Path
from ..shared.tooling import run_tool, which
from ..shared.flags import find_flags
from .evidence import inspect as evidence
def triage(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    out=['FORENSIC TRIAGE','===============']
    for label,argv in [('file',['file',str(p)]),('metadata',['exiftool',str(p)]),('embedded data',['binwalk',str(p)])]:
        if which(argv[0]): out += ['',f'[{label}]',run_tool(argv,timeout=35,max_output=50000)[1] or '(no output)']
        else: out += ['',f'[{label}]',f'skipped: {argv[0]} is not installed']
    if which('strings'):
        text=run_tool(['strings','-a','-n','5',str(p)],timeout=25,max_output=50000)[1]
        interesting=[x for x in text.splitlines() if any(k in x.lower() for k in ('flag','ctf','password','secret','key','http'))]
        out += ['','[interesting strings]','\n'.join(interesting[:100]) or '(none)']
        flags=find_flags(text)
        if flags: out += ['','[possible flags]']+[f'  {x}' for x in flags]
    out += ['',evidence(path),'','Suggested follow-up:','  images -> ctf forensics stego <file>','  archives -> ctf forensics archive <file>','  PCAP -> ctf forensics pcap <file>','  PDF/doc -> ctf forensics metadata <file>']
    return '\n'.join(out)

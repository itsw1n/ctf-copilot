from pathlib import Path
from ..shared.tooling import run_tool, which
def inspect(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    out=['STEGO TRIAGE','============']
    suffix=p.suffix.lower()
    if suffix in {'.png','.bmp'} and which('zsteg'):
        _,t=run_tool(['zsteg',str(p)],timeout=45,max_output=50000); out += ['','[zsteg]',t or '(no output)']
    if suffix in {'.jpg','.jpeg','.bmp','.wav','.au'} and which('steghide'):
        _,t=run_tool(['steghide','info',str(p)],timeout=20,max_output=20000); out += ['','[steghide info]',t or '(no output)']
    if which('binwalk'):
        _,t=run_tool(['binwalk',str(p)],timeout=30,max_output=30000); out += ['','[binwalk]',t or '(no output)']
    if len(out)==2: out.append('No matching stego helper installed for this file type.')
    return '\n'.join(out)

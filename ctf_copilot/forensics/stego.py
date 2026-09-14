from pathlib import Path
from ..shared.tooling import run_tool, which
from ..shared.flags import find_flags_bytes
def inspect(path: str, all_tools: bool=False, extract_to: str|None=None) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    data=p.read_bytes()[:8_000_000]; out=['STEGO TRIAGE','============']
    flags=find_flags_bytes(data)
    if flags: out += ['', '[possible flags]']+[f'  {flag}' for flag in flags]
    suffix=p.suffix.lower()
    if suffix in {'.png','.bmp'} and which('zsteg'):
        _,t=run_tool(['zsteg',str(p)],timeout=45,max_output=50000); out += ['','[zsteg]',t or '(no output)']
    if suffix=='.png' and which('pngcheck'):
        _,t=run_tool(['pngcheck','-v',str(p)],timeout=30,max_output=30000); out += ['','[pngcheck]',t or '(no output)']
    if suffix in {'.png','.jpg','.jpeg','.gif','.bmp'} and which('zbarimg'):
        _,t=run_tool(['zbarimg','--quiet',str(p)],timeout=30,max_output=20000); out += ['','[QR/barcode]',t or '(none)']
    if suffix in {'.jpg','.jpeg','.bmp','.wav','.au'} and which('steghide'):
        _,t=run_tool(['steghide','info',str(p)],timeout=20,max_output=20000); out += ['','[steghide info]',t or '(no output)']
    if which('binwalk'):
        _,t=run_tool(['binwalk',str(p)],timeout=30,max_output=30000); out += ['','[binwalk]',t or '(no output)']
    if suffix in {'.txt','.html','.xml','.js','.py'}:
        text=data.decode('utf-8','ignore'); zero=sum(text.count(x) for x in ('\u200b','\u200c','\u200d','\ufeff'))
        trailing=sum(1 for line in text.splitlines() if line.endswith((' ','\t')))
        if zero or trailing: out += ['',f'[text stego] zero-width={zero} trailing-whitespace-lines={trailing}']
    if extract_to and which('binwalk'):
        _,t=run_tool(['binwalk','-e','-C',extract_to,str(p)],timeout=90,max_output=60000); out += ['', '[extract]',t or '(no output)']
    if len(out)==2: out.append('No matching stego helper installed for this file type.')
    out += ['', 'Next: `ctf forensics evidence <file>` for signatures and embedded data.']
    return '\n'.join(out)

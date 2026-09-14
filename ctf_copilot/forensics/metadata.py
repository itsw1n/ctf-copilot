from pathlib import Path
from ..shared.tooling import run_tool, which
def show(path):
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    out=['METADATA','========']
    if which('exiftool'): out += [run_tool(['exiftool',str(p)],timeout=30,max_output=80000)[1] or '(no metadata output)']
    else: out += ['exiftool is not installed.']
    if p.suffix.lower()=='.pdf':
        for tool,args in [('pdfinfo',['pdfinfo',str(p)]),('pdfid',['pdfid',str(p)])]:
            if which(tool): out += ['',f'[{tool}]',run_tool(args,timeout=30,max_output=50000)[1] or '(no output)']
    if p.suffix.lower() in {'.doc','.docx','.xls','.xlsx','.ppt','.pptx'} and which('olevba'): out += ['', '[olevba]',run_tool(['olevba',str(p)],timeout=45,max_output=60000)[1] or '(no output)']
    out += ['', 'Next: inspect strings or use `ctf forensics triage <file>`.']
    return '\n'.join(out)

from pathlib import Path
from ..shared.tooling import run_tool, which
def show(path):
    p=Path(path)
    if not p.is_file(): raise SystemExit(f'Not a file: {p}')
    if not which('exiftool'): raise SystemExit('exiftool is not installed.')
    print(run_tool(['exiftool',str(p)],timeout=30,max_output=80000)[1] or '(no metadata output)')

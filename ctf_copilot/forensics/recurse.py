from __future__ import annotations
import io, re, zipfile
from pathlib import Path
from ..shared.flags import find_flags
from ..crypto.analyzer import analyze

MAX_FILE=2_000_000
MAX_DEPTH=3
MAX_ENTRIES=250

def _inspect_bytes(name: str, data: bytes, depth: int, out: list[str]):
    if len(data) > MAX_FILE:
        out.append(f'{name}: skipped deep content analysis (>{MAX_FILE} bytes)')
        return
    text=data.decode('utf-8','ignore')
    flags=find_flags(text)
    for flag in flags[:20]: out.append(f'{name}: FLAG {flag}')
    stripped=text.strip()
    if stripped and len(stripped)<=10000:
        results=analyze(stripped,max_depth=4,branch_limit=6,beam_width=8)
        for r in results[:2]:
            chain=' -> '.join(x.kind for x in r.chain)
            if find_flags(r.output):
                out.append(f'{name}: decoded via {chain}: {r.output[:300]}')
    if depth>=MAX_DEPTH: return
    bio=io.BytesIO(data)
    if zipfile.is_zipfile(bio):
        bio.seek(0)
        with zipfile.ZipFile(bio) as z:
            for info in z.infolist()[:MAX_ENTRIES]:
                if info.is_dir() or (info.flag_bits & 1):
                    continue
                try: child=z.read(info)
                except Exception: continue
                _inspect_bytes(f'{name}!/{info.filename}',child,depth+1,out)

def inspect(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    out=['RECURSIVE ARCHIVE TRIAGE','========================',f'Input: {p}']
    data=p.read_bytes()
    if not zipfile.is_zipfile(io.BytesIO(data)):
        out += ['Not a ZIP-compatible archive. This safe recursive helper currently focuses on ZIP nesting.','Use `ctf forensics triage`/`binwalk`/`7z` for other formats.']
        return '\n'.join(out)
    _inspect_bytes(p.name,data,0,out)
    if len(out)==3: out.append('No flags or high-confidence encoded flag clues found in readable/nested ZIP content.')
    out += ['','Safety: files were inspected as data only; nothing was executed.']
    return '\n'.join(out)

from __future__ import annotations
from pathlib import Path
from .crypto.analyzer import analyze as crypto_analyze
from .forensics.triage import triage as forensic_triage
from .reverse.triage import triage as reverse_triage
from .web.analyzer import analyze as web_analyze, render as web_render
from .shared.files import file_report
from .shared.flags import find_flags
from .flags.scanner import scan as flag_scan


def classify_file(p: Path) -> str:
    head=p.read_bytes()[:32]; suffix=p.suffix.lower()
    if head.startswith((b'\x7fELF',b'MZ')): return 'reverse/pwn'
    if suffix in {'.png','.jpg','.jpeg','.gif','.bmp','.webp','.pdf','.pcap','.pcapng','.zip','.7z','.wav'} or head.startswith((b'\x89PNG\r\n\x1a\n',b'\xff\xd8\xff',b'PK\x03\x04')): return 'forensics'
    if suffix in {'.py','.js','.txt','.md','.json','.xml','.html'}: return 'text/misc'
    return 'generic-file'


def solve(target: str) -> str:
    p=Path(target)
    if p.is_dir():
        rows=flag_scan(str(p)); lines=['CTF SOLVE - DIRECTORY','=====================',f'Path: {p}',f'Flag-like hits: {len(rows)}']
        lines += [f'  {path}: {flag}' for path,flag in rows[:50]]
        lines += ['','Next: inspect interesting files individually with `ctf solve <file>`.']
        return '\n'.join(lines)
    if p.is_file():
        cat=classify_file(p); out=['CTF SOLVE - FIRST PASS','======================',f'Input: {p}',f'Suggested category: {cat}','',file_report(p)]
        if cat=='forensics': out += ['',forensic_triage(str(p))]
        elif cat=='reverse/pwn': out += ['',reverse_triage(str(p)),'','Next: `ctf pwn checksec <file>` and `ctf reverse disasm <file>`.']
        elif cat=='text/misc':
            try:
                text=p.read_text(errors='ignore')[:200000]; results=crypto_analyze(text)
                if results: out += ['','Crypto candidates:']+[f'  {" -> ".join(x.kind for x in r.chain)}: {r.output[:200]}' for r in results[:5]]
            except OSError: pass
        return '\n'.join(out)
    if target.startswith(('http://','https://')):
        return 'CTF SOLVE - WEB FIRST PASS\n==========================\n'+web_render(web_analyze(target))+'\n\nActive probes require explicit authorization confirmation:\n  ctf web test <url> --confirm-authorized --headers --methods'
    results=crypto_analyze(target); out=['CTF SOLVE - TEXT FIRST PASS','===========================']
    if not results: out.append('No strong supported encoding/cipher candidate detected.')
    else:
        for i,r in enumerate(results[:5],1):
            chain=' -> '.join(f'{x.kind}({x.parameter})' if x.parameter else x.kind for x in r.chain); out.append(f'{i}. {chain}: {r.output}')
        found=[]
        for r in results: found.extend(find_flags(r.output))
        if found: out += ['','Possible flags:']+[f'  {x}' for x in dict.fromkeys(found)]
    return '\n'.join(out)

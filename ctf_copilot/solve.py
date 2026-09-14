from __future__ import annotations
from pathlib import Path
from .crypto.analyzer import analyze as crypto_analyze
from .forensics.triage import triage as forensic_triage
from .forensics.archive import inspect as archive_inspect
from .reverse.triage import triage as reverse_triage
from .pwn.triage import triage as pwn_triage
from .web.analyzer import analyze as web_analyze, render as web_render
from .shared.files import file_report
from .shared.flags import find_flags
from .flags.scanner import scan as flag_scan


def classify_file(p: Path) -> str:
    head=p.read_bytes()[:32]; suffix=p.suffix.lower()
    if head.startswith((b'\x7fELF',b'MZ')): return 'reverse/pwn'
    if suffix in {'.pcap','.pcapng'}: return 'forensics/pcap'
    if suffix in {'.zip','.7z','.rar','.tar','.gz'} or head.startswith(b'PK\x03\x04'): return 'forensics/archive'
    if suffix in {'.png','.jpg','.jpeg','.gif','.bmp','.webp','.pdf','.wav'} or head.startswith((b'\x89PNG\r\n\x1a\n',b'\xff\xd8\xff')): return 'forensics'
    if suffix in {'.py','.js','.txt','.md','.json','.xml','.html','.csv'}: return 'text/crypto'
    return 'generic-file'


def solve(target: str) -> str:
    p=Path(target)
    if p.is_dir():
        rows=flag_scan(str(p)); lines=['CTF SOLVE - DIRECTORY','=====================',f'Path: {p}',f'Flag-like hits: {len(rows)}']
        lines += [f'  {path}: {flag}' for path,flag in rows[:50]]
        lines += ['','NEXT BEST ACTIONS','  - Inspect suspicious files individually with `ctf solve <file>`.','  - For extracted challenge trees, run `ctf flags scan <directory>`.']
        return '\n'.join(lines)
    if p.is_file():
        cat=classify_file(p); out=['CTF SOLVE - FIRST PASS','======================',f'Input: {p}',f'Suggested category: {cat}','',file_report(p)]
        if cat=='forensics/archive':
            out += ['',archive_inspect(str(p)),'','NEXT BEST ACTIONS','  - `ctf forensics recurse <archive>` for nested ZIP/text clues','  - `ctf forensics triage <archive>` for strings/binwalk clues']
        elif cat.startswith('forensics'):
            out += ['',forensic_triage(str(p))]
            if cat=='forensics/pcap': out += ['','NEXT: `ctf forensics pcap <file>`']
        elif cat=='reverse/pwn':
            out += ['',reverse_triage(str(p)),'',pwn_triage(str(p))]
        elif cat=='text/crypto':
            try:
                text=p.read_text(errors='ignore')[:200000]; results=crypto_analyze(text)
                if results:
                    out += ['','Crypto candidates:']
                    for r in results[:5]:
                        chain=' -> '.join(f'{x.kind}({x.parameter})' if x.parameter else x.kind for x in r.chain)
                        out.append(f'  {chain}: {r.output[:300]}')
            except OSError: pass
        return '\n'.join(out)
    if target.startswith(('http://','https://')):
        return 'CTF SOLVE - WEB FIRST PASS\n==========================\n'+web_render(web_analyze(target))+'\n\nNEXT BEST ACTIONS\n  - `ctf web endpoints <url>`\n  - `ctf web params <url>`\n  - active probes require `--confirm-authorized`'
    results=crypto_analyze(target); out=['CTF SOLVE - TEXT FIRST PASS','===========================']
    if not results:
        out.append('No strong supported encoding/cipher candidate detected.')
        out += ['','NEXT: inspect challenge context or try `ctf crypto decode --kind <known-type>`.']
    else:
        for i,r in enumerate(results[:5],1):
            chain=' -> '.join(f'{x.kind}({x.parameter})' if x.parameter else x.kind for x in r.chain); out.append(f'{i}. {chain}: {r.output}')
        found=[]
        for r in results: found.extend(find_flags(r.output))
        if found: out += ['','Possible flags:']+[f'  {x}' for x in dict.fromkeys(found)]
    return '\n'.join(out)

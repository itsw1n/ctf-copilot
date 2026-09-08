from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from .core import file_report, recursive, flags
from .tooling import binary_triage, forensic_triage
from .web import analyze as web_analyze, render as web_render


def classify_file(p: Path) -> str:
    head=p.read_bytes()[:32]
    suf=p.suffix.lower()
    if head.startswith(b'\x7fELF') or head.startswith(b'MZ'):
        return 'reverse/pwn'
    if head.startswith((b'\x89PNG\r\n\x1a\n',b'\xff\xd8\xff')) or suf in {'.png','.jpg','.jpeg','.gif','.bmp','.webp','.pdf','.pcap','.pcapng','.zip','.7z'}:
        return 'forensics'
    if suf in {'.py','.js','.txt','.md','.json','.xml','.html'}:
        return 'text/misc'
    return 'generic-file'


def solve(target: str) -> str:
    p=Path(target)
    if p.is_file():
        cat=classify_file(p)
        out=['CTF SOLVE - FIRST PASS','======================',f'Input: {p}',f'Suggested category: {cat}','']
        out.append(file_report(p))
        if cat=='forensics':
            out += ['', forensic_triage(p)]
        elif cat=='reverse/pwn':
            out += ['', binary_triage(p)]
        out += ['', 'Next step:', _next_for(cat)]
        return '\n'.join(out)
    if target.startswith(('http://','https://')):
        i=web_analyze(target)
        return 'CTF SOLVE - WEB FIRST PASS\n==========================\n' + web_render(i) + '\n\nNext step:\n  ctf web test <url> --confirm-authorized --headers --methods\n  Add --xss or --sqli when query parameters are present.'
    decoded=recursive(target)
    out=['CTF SOLVE - TEXT FIRST PASS','===========================']
    if decoded:
        out += [f'{d}. {k}: {v}' for d,k,v in decoded]
        found=[]
        for _,_,v in decoded: found += flags(v)
        if found: out += ['','Possible flags:']+[f'  {x}' for x in dict.fromkeys(found)]
    else:
        out.append('No obvious supported encoding chain detected.')
    return '\n'.join(out)


def _next_for(cat: str) -> str:
    return {
        'forensics':'  Inspect extracted/embedded data; use Wireshark for PCAPs and stego tools when the file type fits.',
        'reverse/pwn':'  Run `ctf reverse triage <binary>` for logic clues or `ctf pwn triage <binary>` for exploitation-oriented triage; then use Ghidra/GDB as needed.',
        'text/misc':'  Try `ctf crypto analyze <text>` for encoded text, or inspect scripts/comments and flag patterns.',
        'generic-file':'  Try `ctf forensics triage <file>` and inspect embedded signatures.',
    }[cat]

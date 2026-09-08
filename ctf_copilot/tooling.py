from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def which(name: str) -> str | None:
    return shutil.which(name)


def run_tool(argv: list[str], timeout: int = 45, max_output: int = 120_000) -> tuple[int, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or '') + (('\n' + r.stderr) if r.stderr else '')
        if len(out) > max_output:
            out = out[:max_output] + '\n... output truncated ...'
        return r.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return 124, f'Timed out after {timeout}s: {" ".join(argv)}'
    except OSError as exc:
        return 127, str(exc)


def installed_tools() -> dict[str, bool]:
    names = [
        'file','strings','xxd','curl','wget','jq','openssl','7z','git','python3','pipx',
        'nmap','ffuf','gobuster','sqlmap','nikto','whatweb','john','hashcat',
        'exiftool','binwalk','wireshark','tshark','foremost','steghide','pdfinfo',
        'ghidra','gdb','checksec','objdump','readelf','radare2','rizin','ROPgadget',
        'ropper','pwn','dig','nslookup','nc','socat','tcpdump'
    ]
    return {n: bool(which(n)) for n in names}


def summarize_tools() -> str:
    rows = installed_tools()
    groups = {
        'GENERAL / LINUX': ['file','strings','xxd','curl','wget','jq','openssl','7z','git','python3','pipx'],
        'WEB': ['nmap','ffuf','gobuster','sqlmap','nikto','whatweb'],
        'CRYPTO': ['openssl','john','hashcat','python3'],
        'FORENSICS': ['exiftool','binwalk','wireshark','tshark','foremost','steghide','pdfinfo'],
        'REVERSE': ['ghidra','gdb','objdump','readelf','radare2','rizin'],
        'PWN': ['gdb','checksec','ROPgadget','ropper','pwn'],
        'NETWORK': ['nmap','dig','nslookup','nc','socat','tcpdump','wireshark'],
    }
    out=[]
    for title,names in groups.items():
        out.append(f'=== {title} ===')
        for name in names:
            out.append(f'{name:<12} {"OK" if rows.get(name) else "MISSING"}')
        out.append('')
    return '\n'.join(out).rstrip()


def binary_triage(path: str | Path) -> str:
    p = Path(path)
    if not p.is_file():
        return f'Not a file: {p}'
    out = ['BINARY TRIAGE', '=============']
    commands = [
        ('file', ['file', str(p)]),
        ('checksec', ['checksec', '--file='+str(p)]),
        ('readelf header', ['readelf', '-h', str(p)]),
        ('readelf symbols', ['readelf', '-Ws', str(p)]),
        ('imports/strings', ['strings', '-a', '-n', '4', str(p)]),
    ]
    keywords = ('gets','strcpy','strcat','scanf','printf','system','execve','win','flag','secret','password')
    for label, argv in commands:
        if not which(argv[0]):
            continue
        rc, text = run_tool(argv, timeout=30)
        if label in ('readelf symbols','imports/strings'):
            lines=[ln for ln in text.splitlines() if any(k in ln.lower() for k in keywords)]
            text='\n'.join(lines[:120]) or '(no obvious high-signal matches)'
        out += ['', f'[{label}]', text or f'(exit {rc}, no output)']
    if which('ROPgadget'):
        rc,text=run_tool(['ROPgadget','--binary',str(p),'--only','pop|ret|leave'],timeout=35,max_output=30_000)
        out += ['', '[ROP gadget preview]', '\n'.join(text.splitlines()[:40]) if text else f'(exit {rc})']
    return '\n'.join(out)


def forensic_triage(path: str | Path) -> str:
    p=Path(path)
    if not p.is_file():
        return f'Not a file: {p}'
    out=['FORENSIC TRIAGE','===============']
    for label,argv in [
        ('file',['file',str(p)]),
        ('metadata',['exiftool',str(p)]),
        ('embedded data',['binwalk',str(p)]),
    ]:
        if which(argv[0]):
            _,text=run_tool(argv,timeout=35,max_output=50_000)
            out += ['',f'[{label}]',text or '(no output)']
    if which('strings'):
        _,text=run_tool(['strings','-a','-n','5',str(p)],timeout=25,max_output=50_000)
        interesting=[ln for ln in text.splitlines() if any(k in ln.lower() for k in ('flag','ctf','password','secret','key','http','pk\x03\x04'))]
        out += ['', '[interesting strings]', '\n'.join(interesting[:100]) or '(none)']
    return '\n'.join(out)

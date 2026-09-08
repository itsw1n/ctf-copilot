from __future__ import annotations

import shutil
import subprocess


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

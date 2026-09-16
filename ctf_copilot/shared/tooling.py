from __future__ import annotations
import shutil, subprocess

def which(name): return shutil.which(name)
def run_tool(argv,timeout=45,max_output=120000):
    try:
        r=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
        out=(r.stdout or '')+(('\n'+r.stderr) if r.stderr else '')
        if len(out)>max_output: out=out[:max_output]+'\n... output truncated ...'
        return r.returncode,out.strip()
    except subprocess.TimeoutExpired: return 124,f'Timed out after {timeout}s: {" ".join(argv)}'
    except OSError as e: return 127,str(e)

GROUPS={
'GENERAL':['file','strings','xxd','curl','wget','jq','openssl','7z','git','python3','pipx'],
'WEB':['nmap','ffuf','gobuster','sqlmap','nikto','whatweb'],
'CRYPTO':['openssl','john','hashcat','python3'],
'FORENSICS':['exiftool','binwalk','wireshark','tshark','foremost','steghide','zsteg','pdfinfo'],
'REVERSE':['ghidra','gdb','objdump','readelf','radare2','rizin'],
'PWN':['gdb','checksec','ROPgadget','ropper','pwn'],
'NETWORK':['nmap','dig','nslookup','nc','socat','tcpdump','wireshark'],
}

def summarize_tools():
    out=[]
    for title,names in GROUPS.items():
        out.append(f'=== {title} ===')
        out += [f'{n:<12} {"OK" if which(n) else "MISSING"}' for n in names]; out.append('')
    return '\n'.join(out).rstrip()

def doctor(category=None):
    selected = {category.upper(): GROUPS.get(category.upper(), [])} if category and category.upper() in GROUPS else GROUPS
    missing=[n for names in selected.values() for n in names if not which(n)]
    missing=list(dict.fromkeys(missing))
    lines=['CTF COPILOT TOOL DOCTOR','=======================',f'Missing helpers: {len(missing)}']+[f'  - {x}' for x in missing]
    lines += ['','Install only what you need with your package manager. Some names (for example zsteg/ROPgadget) may be installed via language-specific package managers.']
    return '\n'.join(lines)

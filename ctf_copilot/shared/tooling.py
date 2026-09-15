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

def run_tool_bytes(argv,timeout=45,max_output=2000000):
    """Byte-faithful capture for binary tools (e.g. icat). Returns (rc, raw stdout bytes, capped)."""
    try:
        r=subprocess.run(argv,capture_output=True,timeout=timeout)
        raw=r.stdout or b''
        if len(raw)>max_output: raw=raw[:max_output]
        return r.returncode,raw
    except subprocess.TimeoutExpired: return 124,b''
    except OSError: return 127,b''

# Audited (Task 18): every name here is actually invoked via run_tool/which
# (or referenced by a cracking handoff, marked below). See
# requirements-system.txt for the command -> Kali apt package mapping.
GROUPS={
'GENERAL':['file','strings','7z','7zz','python3'],
'WEB':['nmap'],
# CRYPTO entries are handoff-only: crack_handoff prints john/hashcat/fcrackzip
# commands for the user to run manually; they are never auto-executed.
'CRYPTO':['john','hashcat','fcrackzip','python3'],
'FORENSICS':['file','strings','exiftool','binwalk','pngcheck','zsteg','zbarimg','steghide','tshark','pdfinfo','pdfid','olevba','mmls','fsstat','fls','icat','vol','volatility3','sox','soxi','mediainfo','7z','7zz'],
'REVERSE':['file','strings','readelf','objdump','checksec'],
'PWN':['checksec','ROPgadget','readelf','objdump'],
'NETWORK':['nmap','dig','whois'],
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
    lines += ['','Install only what you need. On Kali, search packages with:','  apt search <tool>','','Some names (for example zsteg/ROPgadget) may be installed via language-specific package managers depending on your Kali setup.']
    return '\n'.join(lines)

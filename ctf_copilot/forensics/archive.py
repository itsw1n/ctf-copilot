from __future__ import annotations
from pathlib import Path
from ..shared.archives import list_entries,detect_crypto,test_password,extract
def inspect(path: str, passwords: list[str] | None = None, crack: bool=False, extract_to: str|None=None) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    lines=['ARCHIVE INSPECTION','==================']
    entries=list_entries(str(p))
    if not entries: return '\n'.join(lines+['Could not list archive entries (install 7z or check file).'])
    crypto=detect_crypto(str(p)); lines += [f'Entries: {len(entries)}',f'Encryption: {crypto}','']
    lines += [f"{x['name']}  size={x['size']} encrypted={x['encrypted']} method={x['method']}" for x in entries[:200]]
    password=None
    if crypto!='none':
        candidates=list(dict.fromkeys([*(passwords or []),p.stem,'password','infected','secret','1234','admin','root','flag','challenge','ctf','test']))[:20]
        lines += ['', 'Password attempts:']
        for candidate in candidates:
            if test_password(str(p),candidate): password=candidate; lines.append(f'  SUCCESS: {candidate!r}'); break
            lines.append(f'  no: {candidate!r}')
        if not password: lines.append('  No candidate worked. Use --crack only if you intend a wordlist attack.')
    if crack and not password: lines.append('Cracking is not automated yet; use fcrackzip/John manually with a controlled wordlist.')
    if extract_to:
        ok,msg=extract(str(p),extract_to,password); lines += ['',f'Extract: {"ok" if ok else "failed"}: {msg[:300]}']
    lines += ['', 'Next: `ctf forensics recurse <archive>` for nested layers.']
    return '\n'.join(lines)

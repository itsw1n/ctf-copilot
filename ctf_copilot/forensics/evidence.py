from __future__ import annotations
from pathlib import Path
from ..shared.files import magic, printable_strings
from ..shared.tooling import which

def inspect(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    data=p.read_bytes()[:8_000_000]; detected=magic(data[:32]); ext=p.suffix.lower()
    out=['FORENSIC EVIDENCE','=================',f'Magic type: {detected}',f'Filename extension: {ext or "(none)"}']
    expected={'.png':'PNG image','.jpg':'JPEG image','.jpeg':'JPEG image','.pdf':'PDF document','.zip':'ZIP archive'}
    if ext in expected and expected[ext]!=detected: out += ['', 'Finding: extension does not match magic bytes.', 'Why it matters: this may be a renamed file or polyglot.', 'Next suggested command: `ctf forensics triage <file>`']
    for sig,name in ((b'PK\x03\x04','ZIP'),(b'%PDF-','PDF'),(b'\x89PNG\r\n\x1a\n','PNG')):
        offset=data.find(sig)
        if offset>0: out += [f'Embedded {name} signature at byte {offset}; use binwalk or archive recursion.']
    text='\n'.join(printable_strings(data))
    if 'base64' in text.lower() or any(len(x)>32 and set(x)<=set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=') for x in text.splitlines()): out += ['Finding: Base64-looking text found in readable content.', 'Next suggested command: `ctf crypto analyze "<copied text>"`.']
    if detected in ('PNG image','JPEG image'):
        tool='zbarimg' if which('zbarimg') else 'exiftool'
        out += [f'Image clue path: inspect metadata and QR/barcodes. Available helper: {tool}.']
    return '\n'.join(out)

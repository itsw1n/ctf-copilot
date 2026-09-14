"""Small, bounded 7z archive wrapper shared by forensic commands."""
from __future__ import annotations
from pathlib import Path
from .tooling import run_tool, which

def _seven() -> str | None: return which('7z') or which('7zz')

def list_entries(path: str) -> list[dict]:
    tool=_seven()
    if not tool: return []
    _,text=run_tool([tool,'l','-slt',path],timeout=45,max_output=120000)
    rows=[]; current={}
    for line in text.splitlines():
        if ' = ' not in line: continue
        key,value=line.split(' = ',1)
        if key=='Path' and current:
            if current.get('Path')!=path: rows.append({'name':current.get('Path',''),'size':current.get('Size','?'),'encrypted':bool(current.get('Encrypted')),'method':current.get('Method','?')})
            current={}
        current[key]=value
    if current and current.get('Path')!=path: rows.append({'name':current.get('Path',''),'size':current.get('Size','?'),'encrypted':bool(current.get('Encrypted')),'method':current.get('Method','?')})
    return rows

def detect_crypto(path: str) -> str:
    entries=list_entries(path)
    if not entries: return 'unknown'
    methods=' '.join(str(x.get('method','')) for x in entries).lower()
    if 'aes' in methods: return 'aes'
    if any(x.get('encrypted') for x in entries): return 'zipcrypto'
    return 'none'

def test_password(path: str,password: str) -> bool:
    tool=_seven()
    if not tool: return False
    rc,_=run_tool([tool,'t',f'-p{password}',path],timeout=45,max_output=40000)
    return rc==0

def extract(path: str,outdir: str,password: str|None=None) -> tuple[bool,str]:
    tool=_seven()
    if not tool: return False,'7z is not installed.'
    Path(outdir).mkdir(parents=True,exist_ok=True)
    args=[tool,'x','-y',f'-o{outdir}']+([f'-p{password}'] if password else [])+[path]
    rc,text=run_tool(args,timeout=90,max_output=80000)
    return rc==0,text or ('extracted' if rc==0 else 'extraction failed')

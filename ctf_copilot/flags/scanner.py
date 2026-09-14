from pathlib import Path
from .patterns import patterns
def find(text,prefix=None):
    out=[]
    for p in patterns(prefix):
        for m in p.findall(text):
            if m not in out: out.append(m)
    return out
def scan(value,prefix=None):
    p=Path(value); results=[]
    if p.is_dir():
        for f in p.rglob('*'):
            if f.is_file() and f.stat().st_size<=10_000_000:
                try:
                    text=f.read_text(errors='ignore')
                    for flag in find(text,prefix): results.append((str(f),flag))
                except OSError: pass
    elif p.is_file():
        for flag in find(p.read_text(errors='ignore'),prefix): results.append((str(p),flag))
    else:
        for flag in find(value,prefix): results.append(('<text>',flag))
    return results

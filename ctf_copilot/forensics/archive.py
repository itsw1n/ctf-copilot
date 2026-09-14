from __future__ import annotations
import zipfile
from pathlib import Path
def inspect(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    lines=['ARCHIVE INSPECTION','==================']
    if zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            infos=z.infolist(); lines += [f'Entries: {len(infos)}',f'Encrypted entries: {sum(bool(i.flag_bits & 1) for i in infos)}','']
            for i in infos[:200]: lines.append(f'{i.filename}  size={i.file_size} encrypted={bool(i.flag_bits & 1)}')
    else: lines.append('Not a ZIP archive. Use 7z/binwalk manually for other archive types.')
    return '\n'.join(lines)

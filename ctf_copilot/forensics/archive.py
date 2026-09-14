from __future__ import annotations
import zipfile
from pathlib import Path
def inspect(path: str, passwords: list[str] | None = None) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    lines=['ARCHIVE INSPECTION','==================']
    if zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            infos=z.infolist(); lines += [f'Entries: {len(infos)}',f'Encrypted entries: {sum(bool(i.flag_bits & 1) for i in infos)}','']
            for i in infos[:200]: lines.append(f'{i.filename}  size={i.file_size} encrypted={bool(i.flag_bits & 1)}')
            encrypted=[i for i in infos if i.flag_bits & 1]
            if encrypted:
                candidates=[x for x in (passwords or []) if x][:20]
                if candidates:
                    lines += ['', 'Password attempts (in-memory, first encrypted entry only):']
                    entry=encrypted[0]
                    for password in candidates:
                        try:
                            z.read(entry,pwd=password.encode())
                            lines.append(f'  SUCCESS: {password!r} opens {entry.filename}')
                            break
                        except (RuntimeError,zipfile.BadZipFile): lines.append(f'  no: {password!r}')
                else: lines += ['', 'Archive is encrypted. Supply clue words with `ctf forensics archive <file> --password <word>`.']
    else: lines.append('Not a ZIP archive. Use 7z/binwalk manually for other archive types.')
    return '\n'.join(lines)

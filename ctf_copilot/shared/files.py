from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

from .flags import find_flags


def printable_strings(data: bytes, minlen: int = 4) -> list[str]:
    pattern = rb'[\x20-\x7e]{%d,}' % minlen
    return [m.decode('ascii', 'ignore') for m in re.findall(pattern, data)]


def sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def magic(head: bytes) -> str:
    signatures = [
        (b'\x1f\x8b', 'GZIP archive'),(b'BZh', 'BZIP2 archive'),(b'\xfd7zXZ\x00', 'XZ archive'),
        (b'7z\xbc\xaf\x27\x1c', '7Z archive'),(b'Rar!\x1a\x07', 'RAR archive'),
        (b'\xff\xd8\xff', 'JPEG image'),
        (b'\x89PNG\r\n\x1a\n', 'PNG image'),
        (b'GIF87a', 'GIF image'),(b'GIF89a', 'GIF image'),(b'BM', 'BMP image'),(b'II*\x00', 'TIFF image'),(b'MM\x00*', 'TIFF image'),
        (b'%PDF-', 'PDF document'),
        (b'PK\x03\x04', 'ZIP archive'),
        (b'OggS', 'OGG media'),(b'fLaC', 'FLAC audio'),(b'RIFF', 'RIFF/WAV media'),(b'ID3', 'MP3 audio'),
        (b'\x7fELF', 'ELF executable'),
        (b'MZ', 'PE/Windows executable'),
        (b'SQLite format 3\x00', 'SQLite database'),(b'\xd4\xc3\xb2\xa1', 'PCAP capture'),(b'\x0a\x0d\x0d\x0a', 'PCAPNG capture'),
        (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'OLE/CFB document'),(b'{\\rtf', 'RTF document'),
    ]
    for signature, name in signatures:
        if head.startswith(signature):
            return name
    return 'Unknown / generic binary'


def file_report(path: str | Path) -> str:
    p = Path(path)
    if not p.is_file():
        return f'Not a file: {p}'
    size = p.stat().st_size
    with p.open('rb') as fh:
        sample = fh.read(min(size, 8_000_000))
    strings = printable_strings(sample)
    zip_offset = sample.find(b'PK\x03\x04')
    lines = [
        'FILE ANALYSIS', '=============', f'Path: {p}', f'Type: {magic(sample[:32])}',
        f'Size: {size} bytes', f'SHA256: {sha256(p)}', '', 'Hex preview:', sample[:64].hex(' '),
    ]
    found = find_flags('\n'.join(strings))
    if found:
        lines += ['', 'Possible flags:'] + [f'  {item}' for item in found]
    if zip_offset > 0:
        lines += ['', f'Interesting: ZIP signature at byte offset {zip_offset}']
    if size > len(sample):
        lines += ['', f'Note: strings/signature preview limited to first {len(sample)} bytes.']
    if zipfile.is_zipfile(p):
        try:
            with zipfile.ZipFile(p) as archive:
                lines += ['', 'ZIP entries:'] + [
                    f'  {info.filename} ({info.file_size} bytes)' for info in archive.infolist()[:100]
                ]
        except Exception:
            pass
    executable = shutil.which('exiftool')
    if executable:
        try:
            result = subprocess.run([executable, '-j', str(p)], capture_output=True, text=True, timeout=20)
            parsed = json.loads(result.stdout)[0]
            lines += ['', 'Metadata:'] + [f'  {k}: {str(v)[:160]}' for k, v in list(parsed.items())[:25]]
        except Exception:
            pass
    lines += ['', 'Printable strings:'] + [f'  {item[:160]}' for item in strings[:80]]
    return '\n'.join(lines)

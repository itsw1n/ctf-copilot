from __future__ import annotations

import base64
import codecs
import hashlib
import json
import re
import shutil
import socket
import subprocess
import urllib.parse
import zipfile
from pathlib import Path

FLAG_PATTERNS = [
    re.compile(r"\b(?:flag|ctf|picoCTF|HTB|THM)\{[^{}\r\n]{1,300}\}", re.I),
    re.compile(r"\b[A-Za-z0-9_-]{2,24}\{[^{}\r\n]{1,300}\}"),
]


def flags(text: str) -> list[str]:
    out: list[str] = []
    for pattern in FLAG_PATTERNS:
        for match in pattern.findall(text):
            if match not in out:
                out.append(match)
    return out


def strings(data: bytes, minlen: int = 4) -> list[str]:
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
        (b'\xff\xd8\xff', 'JPEG image'),
        (b'\x89PNG\r\n\x1a\n', 'PNG image'),
        (b'%PDF-', 'PDF document'),
        (b'PK\x03\x04', 'ZIP archive'),
        (b'\x7fELF', 'ELF executable'),
        (b'MZ', 'PE/Windows executable'),
    ]
    for signature, name in signatures:
        if head.startswith(signature):
            return name
    return 'Unknown / generic binary'


def decode(kind: str, value: str) -> str:
    raw = value.strip()
    if kind == 'base64':
        cleaned = re.sub(r'\s+', '', raw).replace('-', '+').replace('_', '/')
        cleaned += '=' * ((4 - len(cleaned) % 4) % 4)
        return base64.b64decode(cleaned).decode('utf-8', 'replace')
    if kind == 'base32':
        cleaned = re.sub(r'\s+', '', raw).upper()
        cleaned += '=' * ((8 - len(cleaned) % 8) % 8)
        return base64.b32decode(cleaned).decode('utf-8', 'replace')
    if kind == 'hex':
        return bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', raw)).decode('utf-8', 'replace')
    if kind == 'ascii':
        return ''.join(chr(int(x)) for x in re.findall(r'\d+', raw))
    if kind == 'binary':
        cleaned = re.sub(r'\s+', '', raw)
        if len(cleaned) % 8:
            raise ValueError('Binary input length must be divisible by 8 bits.')
        return ''.join(chr(int(cleaned[i:i + 8], 2)) for i in range(0, len(cleaned), 8))
    if kind == 'url':
        return urllib.parse.unquote_plus(raw)
    if kind == 'rot13':
        return codecs.decode(raw, 'rot_13')
    if kind == 'atbash':
        out = []
        for ch in raw:
            if 'a' <= ch <= 'z':
                out.append(chr(ord('z') - (ord(ch) - ord('a'))))
            elif 'A' <= ch <= 'Z':
                out.append(chr(ord('Z') - (ord(ch) - ord('A'))))
            else:
                out.append(ch)
        return ''.join(out)
    raise ValueError(f'Unsupported decoder: {kind}')


def detect(value: str) -> list[str]:
    raw = value.strip()
    compact = re.sub(r'\s+', '', raw)
    out: list[str] = []
    if len(compact) >= 8 and re.fullmatch(r'[A-Za-z0-9+/=_-]+', compact):
        out.append('base64')
    if re.fullmatch(r'(?:[0-9a-fA-F]{2}[\s:]*){2,}', raw):
        out.append('hex')
    if re.fullmatch(r'(?:\d{1,3}[\s,]+)*\d{1,3}', raw):
        out.append('ascii')
    if re.fullmatch(r'(?:[01]{8}\s*){2,}', raw):
        out.append('binary')
    if '%' in raw or '+' in raw:
        out.append('url')
    return list(dict.fromkeys(out))


def auto(value: str) -> list[tuple[str, str]]:
    out = []
    for kind in detect(value):
        try:
            decoded = decode(kind, value)
            if decoded != value:
                out.append((kind, decoded))
        except Exception:
            pass
    return out


def _text_score(text: str) -> float:
    if not text:
        return -1.0
    printable = sum(1 for ch in text if ch in '\n\r\t' or 32 <= ord(ch) <= 126) / len(text)
    replacement = text.count('�') / len(text)
    flag_signal = 2.0 if flags(text) else 0.0
    words = sum(text.lower().count(x) for x in ('flag', 'ctf', 'http', 'password', 'secret')) * 0.15
    return printable - replacement * 2 + flag_signal + words


def recursive(value: str, depth: int = 6) -> list[tuple[int, str, str]]:
    out = []
    current = value
    seen = {value}
    for level in range(1, depth + 1):
        candidates = auto(current)
        if not candidates:
            break
        kind, decoded = max(candidates, key=lambda row: _text_score(row[1]))
        if decoded in seen:
            break
        seen.add(decoded)
        out.append((level, kind, decoded))
        current = decoded
        if flags(decoded):
            break
    return out


def caesar(value: str):
    for shift in range(1, 26):
        out = ''.join(
            chr((ord(ch) - ord('a') - shift) % 26 + ord('a')) if 'a' <= ch <= 'z'
            else chr((ord(ch) - ord('A') - shift) % 26 + ord('A')) if 'A' <= ch <= 'Z'
            else ch
            for ch in value
        )
        yield shift, out


def xor_candidates(hex_value: str) -> list[tuple[float, int, str]]:
    data = bytes.fromhex(re.sub(r'\s+', '', hex_value))
    rows = []
    for key in range(256):
        text = bytes(b ^ key for b in data).decode('latin1')
        score = sum(ch.isprintable() for ch in text) / max(1, len(text))
        if flags(text):
            score += 2
        rows.append((score, key, text))
    return sorted(rows, reverse=True)[:10]


def resolve(host: str) -> list[str]:
    return list(dict.fromkeys(info[4][0] for info in socket.getaddrinfo(host, None)))


def scan(host: str, ports: list[int] | None = None, timeout: float = .4) -> list[tuple[int, str]]:
    ports = ports or [21,22,23,25,53,80,110,143,443,445,3000,3306,5432,6379,8000,8080,8443]
    out = []
    for port in ports:
        try:
            family = socket.AF_INET6 if ':' in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((host, port)) == 0:
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service = 'unknown'
                    out.append((port, service))
        except OSError:
            pass
    return out


def nmap(host: str) -> str | None:
    executable = shutil.which('nmap')
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable, '-sV', '--version-light', '-Pn', host],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return result.stdout.strip() or None


def file_report(path: str | Path) -> str:
    p = Path(path)
    if not p.is_file():
        return f'Not a file: {p}'
    size = p.stat().st_size
    # Read a bounded sample for strings/signatures so multi-GB forensic files do not fill RAM.
    with p.open('rb') as fh:
        sample = fh.read(min(size, 8_000_000))
    printable = strings(sample)
    zip_offset = sample.find(b'PK\x03\x04')
    lines = [
        'FILE ANALYSIS',
        '=============',
        f'Path: {p}',
        f'Type: {magic(sample[:32])}',
        f'Size: {size} bytes',
        f'SHA256: {sha256(p)}',
        '',
        'Hex preview:',
        sample[:64].hex(' '),
    ]
    found_flags = flags('\n'.join(printable))
    if found_flags:
        lines += ['', 'Possible flags:'] + [f'  {x}' for x in found_flags]
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
    lines += ['', 'Printable strings:'] + [f'  {x[:160]}' for x in printable[:80]]
    return '\n'.join(lines)

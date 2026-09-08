from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from .commands_text import COMMANDS
from .core import caesar, decode, recursive, strings, xor_candidates
from .solve import solve as solve_target
from .tooling import binary_triage, forensic_triage, run_tool, summarize_tools, which


def _print_lines(rows):
    for row in rows:
        print(row)


def _crypto_analyze(value: str) -> None:
    rows = recursive(value)
    if not rows:
        print('No obvious supported encoding chain detected.')
        return
    for depth, kind, text in rows:
        print(f'{depth}. {kind}: {text}')


def _crypto_decode(value: str, kind: str) -> None:
    if kind == 'auto':
        rows = recursive(value)
        if rows:
            for depth, name, text in rows:
                print(f'{depth}. {name}: {text}')
        else:
            print('No obvious supported encoding detected.')
    elif kind == 'caesar':
        for shift, text in caesar(value):
            print(f'{shift:2}: {text}')
    else:
        print(decode(kind, value))


def _forensics_metadata(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('exiftool'):
        raise SystemExit('exiftool is not installed.')
    _, out = run_tool(['exiftool', str(p)], timeout=30, max_output=80_000)
    print(out or '(no metadata output)')


def _forensics_strings(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if which('strings'):
        _, out = run_tool(['strings', '-a', '-n', '4', str(p)], timeout=30, max_output=120_000)
        print(out or '(no printable strings)')
    else:
        data = p.read_bytes()[:8_000_000]
        _print_lines(strings(data))


def _forensics_hex(path: str, count: int) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    with p.open('rb') as fh:
        print(fh.read(count).hex(' '))


def _reverse_strings(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('strings'):
        raise SystemExit('strings is not installed.')
    _, out = run_tool(['strings', '-a', '-n', '4', str(p)], timeout=30, max_output=120_000)
    keywords = ('flag','password','correct','wrong','secret','admin','success','fail','key')
    hits = [line for line in out.splitlines() if any(k in line.lower() for k in keywords)]
    _print_lines(hits or ['No obvious high-signal strings found.'])


def _reverse_disasm(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('objdump'):
        raise SystemExit('objdump is not installed.')
    _, out = run_tool(['objdump', '-d', str(p)], timeout=45, max_output=120_000)
    print(out or '(no disassembly output)')


def _pwn_checksec(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('checksec'):
        raise SystemExit('checksec is not installed.')
    _, out = run_tool(['checksec', '--file=' + str(p)], timeout=30, max_output=40_000)
    print(out or '(no checksec output)')


def _pwn_rop(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        raise SystemExit(f'Not a file: {p}')
    if not which('ROPgadget'):
        raise SystemExit('ROPgadget is not installed.')
    _, out = run_tool(['ROPgadget', '--binary', str(p), '--only', 'pop|ret|leave'], timeout=45, max_output=80_000)
    print(out or '(no matching gadgets found)')


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='ctf',
        description='CTF Copilot v0.5 - one clear command group per CTF category',
    )
    sub = p.add_subparsers(dest='cmd', required=True)

    q = sub.add_parser('solve', help="First command when you don't know where to start")
    q.add_argument('target', help='File, URL, or text')
    q.set_defaults(fn=lambda a: print(solve_target(a.target)))

    q = sub.add_parser('crypto', help='Cryptography and encoding helpers')
    crypto = q.add_subparsers(dest='action', required=True)
    z = crypto.add_parser('analyze', help='Detect and follow likely encoding layers')
    z.add_argument('value'); z.set_defaults(fn=lambda a: _crypto_analyze(a.value))
    z = crypto.add_parser('decode', help='Decode text; defaults to automatic recursive decoding')
    z.add_argument('value'); z.add_argument('--kind', default='auto', choices=['auto','base64','base32','hex','ascii','binary','url','rot13','atbash','caesar'])
    z.set_defaults(fn=lambda a: _crypto_decode(a.value, a.kind))
    z = crypto.add_parser('xor', help='Try single-byte XOR candidates from hex input')
    z.add_argument('value'); z.set_defaults(fn=lambda a: _print_lines(f'key=0x{k:02x} score={score:.3f} text={text[:120]}' for score, k, text in xor_candidates(a.value)))
    z = crypto.add_parser('frequency', help='Character-frequency analysis')
    z.add_argument('value'); z.set_defaults(fn=lambda a: _print_lines(f'{repr(ch)} {count}' for ch, count in Counter(a.value).most_common()))

    q = sub.add_parser('forensics', help='Forensics triage and inspection')
    forensic = q.add_subparsers(dest='action', required=True)
    z = forensic.add_parser('triage', help='file + metadata + binwalk + interesting strings')
    z.add_argument('path'); z.set_defaults(fn=lambda a: print(forensic_triage(a.path)))
    z = forensic.add_parser('metadata', help='Show metadata with ExifTool')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _forensics_metadata(a.path))
    z = forensic.add_parser('strings', help='Extract printable strings')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _forensics_strings(a.path))
    z = forensic.add_parser('hex', help='Show beginning of file as hex')
    z.add_argument('path'); z.add_argument('--bytes', type=int, default=256)
    z.set_defaults(fn=lambda a: _forensics_hex(a.path, max(1, min(a.bytes, 4096))))

    q = sub.add_parser('reverse', help='Reverse-engineering helpers')
    reverse = q.add_subparsers(dest='action', required=True)
    z = reverse.add_parser('triage', help='Binary first pass: file/checksec/readelf/strings/ROP preview')
    z.add_argument('path'); z.set_defaults(fn=lambda a: print(binary_triage(a.path)))
    z = reverse.add_parser('strings', help='Show high-signal reversing strings')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _reverse_strings(a.path))
    z = reverse.add_parser('disasm', help='Disassemble with objdump')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _reverse_disasm(a.path))

    q = sub.add_parser('pwn', help='Binary-exploitation helpers')
    pwn = q.add_subparsers(dest='action', required=True)
    z = pwn.add_parser('triage', help='Binary/pwn first pass')
    z.add_argument('path'); z.set_defaults(fn=lambda a: print(binary_triage(a.path)))
    z = pwn.add_parser('checksec', help='Show NX/PIE/Canary/RELRO')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _pwn_checksec(a.path))
    z = pwn.add_parser('rop', help='Preview useful ROP gadgets')
    z.add_argument('path'); z.set_defaults(fn=lambda a: _pwn_rop(a.path))

    q = sub.add_parser('tools', help='Audit useful Kali/CTF tools installed on this machine')
    q.set_defaults(fn=lambda a: print(summarize_tools()))

    q = sub.add_parser('commands', help='Show the compact categorized command reference')
    q.set_defaults(fn=lambda a: print(COMMANDS))

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()

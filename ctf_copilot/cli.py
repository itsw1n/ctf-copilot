from __future__ import annotations

import argparse
from collections import Counter

from .commands_text import COMMANDS
from .core import caesar, decode, recursive, xor_candidates
from .solve import solve as solve_target
from .tooling import summarize_tools


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

from __future__ import annotations

import argparse

from .commands_text import COMMANDS
from .solve import solve as solve_target
from .tooling import summarize_tools


def _print_lines(rows):
    for row in rows:
        print(row)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='ctf',
        description='CTF Copilot v0.5 - one clear command group per CTF category',
    )
    sub = p.add_subparsers(dest='cmd', required=True)

    q = sub.add_parser('solve', help="First command when you don't know where to start")
    q.add_argument('target', help='File, URL, or text')
    q.set_defaults(fn=lambda a: print(solve_target(a.target)))

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

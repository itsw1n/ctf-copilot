from __future__ import annotations
import argparse
from .solve import solve
from .shared.tooling import summarize_tools, doctor
from .crypto import commands as crypto
from .web import commands as web
from .forensics import commands as forensics
from .reverse import commands as reverse
from .pwn import commands as pwn
from .network import commands as network
from .osint import commands as osint
from .misc import commands as misc
from .workspace import commands as workspace
from .flags import commands as flags


def build_parser() -> argparse.ArgumentParser:
    parser=argparse.ArgumentParser(prog='ctf',description='CTF Copilot v0.7 - modular first-pass CTF assistant')
    sub=parser.add_subparsers(dest='cmd',required=True)
    q=sub.add_parser('solve',help="Unknown challenge? Start here")
    q.add_argument('target',help='File, URL, directory, or text')
    q.set_defaults(fn=lambda a: print(solve(a.target)))
    for mod in (web,crypto,forensics,reverse,pwn,network,osint,misc,workspace,flags): mod.register(sub)
    q=sub.add_parser('tools',help='Audit useful Kali/CTF tools')
    q.add_argument('--doctor',action='store_true',help='Show missing tools and install hints')
    q.set_defaults(fn=lambda a: print(doctor() if a.doctor else summarize_tools()))
    return parser

def main():
    args=build_parser().parse_args(); args.fn(args)

if __name__=='__main__': main()

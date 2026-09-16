from __future__ import annotations
import argparse
import json
from .solve import solve
from .shared.tooling import summarize_tools, doctor
from .commands_text import render_commands
from .shared.style import supports_color
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
from .workspace.manager import load_report


def build_parser() -> argparse.ArgumentParser:
    parser=argparse.ArgumentParser(
        prog='ctf',
        description='CTF Copilot v0.8 - evidence-driven first-pass CTF assistant',
        epilog='Tip: use `ctf commands` for a beginner-friendly command guide.'
    )
    parser.add_argument('--no-color', action='store_true', help='Disable ANSI colors')
    sub=parser.add_subparsers(dest='cmd',required=True)
    q=sub.add_parser('solve',help='Unknown challenge? Start here',description='Classify an unknown file, URL, directory, binary, or encoded text and run a safe first pass.')
    q.add_argument('target',help='File, URL, directory, or text')
    q.add_argument('--description',default='',help='Challenge prompt or hint text')
    q.add_argument('--description-file',help='Read challenge prompt from a file')
    q.add_argument('--flag-pattern',help='Additional regular expression for the event flag format')
    q.add_argument('--workspace',help='Save a structured report under this workspace')
    q.add_argument('--input',action='append',default=[],help='Related value or file; repeat for multiple inputs')
    q.add_argument('--budget',default='balanced',choices=['fast','balanced','deep'],help='Analysis budget profile')
    q.set_defaults(fn=lambda a: print(solve(a.target, open(a.description_file,encoding='utf-8').read() if a.description_file else a.description, a.flag_pattern, a.workspace, a.input, a.budget)))
    for mod in (web,crypto,forensics,reverse,pwn,network,osint,misc,workspace,flags): mod.register(sub)
    q=sub.add_parser('tools',help='Audit useful Kali/CTF tools',description='Check which external helpers CTF Copilot can orchestrate.')
    q.add_argument('--doctor',action='store_true',help='Show missing tools and install/search hints')
    q.add_argument('--category',choices=['web','crypto','forensics','reverse','pwn','network'],help='Limit doctor output to one category')
    q.set_defaults(fn=lambda a: print(doctor(a.category) if a.doctor else summarize_tools()))
    q=sub.add_parser('report',help='Show a saved structured workspace report')
    q.add_argument('workspace')
    q.set_defaults(fn=lambda a: print(json.dumps(load_report(a.workspace), indent=2) if load_report(a.workspace) else 'No solve report found. Run ctf solve ... --workspace <name>.'))
    q=sub.add_parser('commands',help='Show beginner-friendly command guide',description='Print what each command is for and when to use it.')
    q.add_argument('--all',dest='show_all',action='store_true',help='Include specialist commands hidden from --help')
    q.set_defaults(fn=lambda a: print(render_commands(use_color=supports_color(getattr(a, 'no_color', False)), show_all=getattr(a, 'show_all', False))))
    return parser

def main():
    args=build_parser().parse_args(); args.fn(args)

if __name__=='__main__': main()

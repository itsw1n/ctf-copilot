from .triage import triage
from .strings import show as strings
from .symbols import show as symbols
from .disasm import show as disasm
from .analysis import functions, imports

def register(sub):
    q=sub.add_parser('reverse',help='Understand what a compiled program does',description='Use when a CTF gives you a binary/program and you need to find checks, secrets, functions, or control flow.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('triage',help='Binary first pass',description='Best first reverse command: identify file/protections plus high-signal symbols and strings.'); z.add_argument('path'); z.set_defaults(fn=lambda a: print(triage(a.path)))
    z=sp.add_parser('strings',help='High-signal strings',description='Find readable passwords, success/failure messages, flags, URLs and keys embedded in the binary.'); z.add_argument('path'); z.set_defaults(fn=lambda a: strings(a.path))
    z=sp.add_parser('symbols',help='ELF symbol table',description='Show named functions/variables when symbols are available.'); z.add_argument('path'); z.set_defaults(fn=lambda a: symbols(a.path))
    z=sp.add_parser('functions',help='Highlight interesting named functions',description='Quickly surface main/check/win/flag/decrypt-style functions before disassembly.'); z.add_argument('path'); z.set_defaults(fn=lambda a: print(functions(a.path)))
    z=sp.add_parser('imports',help='Highlight interesting imported functions',description='Find comparison/input/system functions that often reveal where to investigate.'); z.add_argument('path'); z.set_defaults(fn=lambda a: print(imports(a.path)))
    z=sp.add_parser('disasm',help='objdump disassembly',description='Use after you identify a function worth inspecting closely.'); z.add_argument('path'); z.add_argument('--function'); z.set_defaults(fn=lambda a: disasm(a.path,a.function))

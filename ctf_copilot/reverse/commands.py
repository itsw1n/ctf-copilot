from .triage import triage
from .strings import show as strings
from .symbols import show as symbols
from .disasm import show as disasm
def register(sub):
    q=sub.add_parser('reverse',help='Reverse-engineering helpers'); sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('triage',help='Binary first pass'); z.add_argument('path'); z.set_defaults(fn=lambda a: print(triage(a.path)))
    z=sp.add_parser('strings',help='High-signal strings'); z.add_argument('path'); z.set_defaults(fn=lambda a: strings(a.path))
    z=sp.add_parser('symbols',help='ELF symbol table'); z.add_argument('path'); z.set_defaults(fn=lambda a: symbols(a.path))
    z=sp.add_parser('disasm',help='objdump disassembly'); z.add_argument('path'); z.add_argument('--function'); z.set_defaults(fn=lambda a: disasm(a.path,a.function))

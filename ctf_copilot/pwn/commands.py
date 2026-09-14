from .triage import triage
from .checksec import show as checksec
from .rop import show as rop
from .cyclic import create, offset

def register(sub):
    q=sub.add_parser('pwn',help='Investigate/exploit bugs in challenge binaries',description='Use when a binary may have memory-corruption, format-string, or control-flow vulnerabilities.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('triage',help='Protection/import analysis with next-step hints',description='Best first pwn command: explain protections and suspicious imports, then suggest likely directions.'); z.add_argument('path'); z.set_defaults(fn=lambda a: print(triage(a.path)))
    z=sp.add_parser('checksec',help='Show NX/PIE/Canary/RELRO',description='Use to learn which common binary protections are enabled.'); z.add_argument('path'); z.set_defaults(fn=lambda a: checksec(a.path))
    z=sp.add_parser('rop',help='Preview useful ROP gadgets',description='Use later when you need reusable instruction sequences for return-oriented programming.'); z.add_argument('path'); z.set_defaults(fn=lambda a: rop(a.path))
    z=sp.add_parser('cyclic',help='Create crash pattern or find exact offset',description='Use for buffer-overflow debugging: create a unique pattern, crash the program, then find the overwritten value offset.'); z.add_argument('action',choices=['create','offset']); z.add_argument('value'); z.set_defaults(fn=lambda a: print(create(int(a.value)) if a.action=='create' else offset(a.value)))

from ..reverse.triage import triage
from .checksec import show as checksec
from .rop import show as rop
from .cyclic import create, offset
def register(sub):
    q=sub.add_parser('pwn',help='Binary exploitation helpers'); sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('triage',help='Binary/pwn first pass'); z.add_argument('path'); z.set_defaults(fn=lambda a: print(triage(a.path)))
    z=sp.add_parser('checksec',help='Show NX/PIE/Canary/RELRO'); z.add_argument('path'); z.set_defaults(fn=lambda a: checksec(a.path))
    z=sp.add_parser('rop',help='Preview useful ROP gadgets'); z.add_argument('path'); z.set_defaults(fn=lambda a: rop(a.path))
    z=sp.add_parser('cyclic',help='Create cyclic pattern or find offset'); z.add_argument('action',choices=['create','offset']); z.add_argument('value'); z.set_defaults(fn=lambda a: print(create(int(a.value)) if a.action=='create' else offset(a.value)))

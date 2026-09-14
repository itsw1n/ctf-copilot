from .domain import inspect
from .username import leads
def register(sub):
    q=sub.add_parser('osint',help='Passive public-information helpers'); sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('domain'); z.add_argument('domain'); z.set_defaults(fn=lambda a: inspect(a.domain))
    z=sp.add_parser('username'); z.add_argument('username'); z.set_defaults(fn=lambda a: [print(f'{n:<8} {u}') for n,u in leads(a.username)])

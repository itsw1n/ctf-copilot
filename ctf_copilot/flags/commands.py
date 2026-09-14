from .scanner import scan
def register(sub):
    q=sub.add_parser('flags',help='Recursive flag scanning'); sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('scan'); z.add_argument('value'); z.add_argument('--prefix'); z.set_defaults(fn=lambda a:_scan(a))
def _scan(a):
    rows=scan(a.value,a.prefix)
    if not rows: print('No flag-like strings found.')
    else:
        for path,flag in rows: print(f'{path}: {flag}')

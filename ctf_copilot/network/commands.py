from ..shared.tooling import run_tool, which
from .resolve import resolve
from .scan import scan
from .dns import lookup
from .connect import connect
def register(sub):
    q=sub.add_parser('network',help='Network/recon helpers for authorized CTF targets'); sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('resolve',help='Resolve host to IPs'); z.add_argument('host'); z.set_defaults(fn=lambda a:[print(x) for x in resolve(a.host)])
    z=sp.add_parser('scan',help='Check common/supplied TCP ports'); z.add_argument('host'); z.add_argument('--ports'); z.add_argument('--timeout',type=float,default=.4); z.set_defaults(fn=lambda a:_scan(a))
    z=sp.add_parser('services',help='Nmap version detection'); z.add_argument('host'); z.set_defaults(fn=lambda a: print(run_tool(['nmap','-sV','--version-light','-Pn',a.host],timeout=90,max_output=100000)[1] if which('nmap') else 'nmap is not installed.'))
    z=sp.add_parser('dns',help='Query common DNS record types'); z.add_argument('domain'); z.set_defaults(fn=lambda a: print(lookup(a.domain)))
    z=sp.add_parser('connect',help='TCP connect and read initial banner'); z.add_argument('host'); z.add_argument('port',type=int); z.set_defaults(fn=lambda a: print(connect(a.host,a.port)))
def _scan(a):
    ports=[int(x) for x in a.ports.split(',')] if a.ports else None
    rows=scan(a.host,ports,a.timeout); [print(f'{p}/tcp OPEN {s}') for p,s in rows] if rows else print('No tested TCP ports were open.')

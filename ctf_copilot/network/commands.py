from ..shared.tooling import run_tool, which
from .resolve import resolve
from .scan import scan
from .dns import lookup
from .connect import connect

SUGGEST={21:'FTP -> check challenge instructions/anonymous access if authorized',22:'SSH -> note banner/version; credentials may come from another challenge step',53:'DNS -> run `ctf network dns <domain>`',80:'HTTP -> run `ctf web analyze http://<host>`',443:'HTTPS -> run `ctf web analyze https://<host>`',445:'SMB -> enumerate shares with an appropriate Kali SMB tool',8000:'HTTP alt -> run web analysis',8080:'HTTP alt -> run web analysis',8443:'HTTPS alt -> run web analysis'}
def register(sub):
    q=sub.add_parser('network',help='Discover services on authorized CTF hosts',description='Use when a challenge gives you a hostname/IP/service port and you need to discover what is exposed.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('resolve',help='Resolve hostname to IPs',description='Use when a challenge gives you a hostname and you want its IP address(es).'); z.add_argument('host'); z.set_defaults(fn=lambda a:[print(x) for x in resolve(a.host)])
    z=sp.add_parser('scan',help='Quick common TCP-port scan + next-step hints',description='Use first on an authorized host to discover common services and what category to investigate next.'); z.add_argument('host'); z.add_argument('--ports'); z.add_argument('--timeout',type=float,default=.4); z.set_defaults(fn=lambda a:_scan(a))
    z=sp.add_parser('services',help='Nmap service/version detection',description='Use after discovering open ports to identify the software/version behind services.'); z.add_argument('host'); z.set_defaults(fn=lambda a: print(run_tool(['nmap','-sV','--version-light','-Pn',a.host],timeout=90,max_output=100000)[1] if which('nmap') else 'nmap is not installed.'))
    z=sp.add_parser('dns',help='Query common DNS records',description='Use for domain/DNS challenges to inspect A/AAAA/MX/TXT/CNAME-style clues.'); z.add_argument('domain'); z.set_defaults(fn=lambda a: print(lookup(a.domain)))
    z=sp.add_parser('connect',help='TCP connect and read initial banner',description='Use for nc-style CTF services to see the server greeting/banner.'); z.add_argument('host'); z.add_argument('port',type=int); z.set_defaults(fn=lambda a: print(connect(a.host,a.port)))
def _scan(a):
    ports=[int(x) for x in a.ports.split(',')] if a.ports else None
    rows=scan(a.host,ports,a.timeout)
    if not rows: print('No tested TCP ports were open.'); return
    for p,s in rows: print(f'{p}/tcp OPEN {s}')
    print('\nNEXT BEST ACTIONS')
    for p,_ in rows:
        hint=SUGGEST.get(p)
        if hint: print(f'  {p}: {hint}')

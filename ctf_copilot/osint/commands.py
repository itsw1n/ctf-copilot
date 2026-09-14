from .domain import inspect
from .username import leads
def register(sub):
    q=sub.add_parser('osint',help='Passive public-information helpers',description='Use for public-information challenges. These helpers generate clues/leads; verify them manually.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('domain',help='Inspect public domain clues',description='Use when the challenge gives a domain and you want passive DNS/WHOIS-style information.'); z.add_argument('domain'); z.set_defaults(fn=lambda a: inspect(a.domain))
    z=sp.add_parser('username',help='Generate profile-search leads',description='Use when a challenge gives a username and you want common public profile URLs to verify manually.'); z.add_argument('username'); z.set_defaults(fn=lambda a: [print(f'{n:<8} {u}') for n,u in leads(a.username)])

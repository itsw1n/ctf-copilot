from ..network.resolve import resolve
from ..network.dns import lookup
from ..shared.tooling import run_tool, which
def inspect(domain):
    print('Domain:',domain); print('Resolved IPs:'); [print('  '+x) for x in resolve(domain)]; print('\nDNS:\n'+lookup(domain))
    if which('whois'): print('\nWHOIS:\n'+run_tool(['whois',domain],timeout=30,max_output=50000)[1])

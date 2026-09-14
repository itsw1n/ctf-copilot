from ..shared.tooling import run_tool, which
def lookup(domain):
    if which('dig'):
        rows=[]
        for typ in ('A','AAAA','MX','TXT','CNAME'):
            out=run_tool(['dig','+short',domain,typ],timeout=20,max_output=20000)[1]
            if out: rows.append(f'[{typ}]\n{out}')
        return '\n\n'.join(rows) or 'No DNS records returned.'
    import socket
    return '\n'.join(sorted(set(x[4][0] for x in socket.getaddrinfo(domain,None))))

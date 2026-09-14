from pathlib import Path
from ..shared.tooling import run_tool, which
def summarize(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    if not which('tshark'): return 'tshark is not installed. Open the capture in Wireshark.'
    out=['PCAP SUMMARY','============']
    for title,args in [('protocol hierarchy',['tshark','-r',str(p),'-q','-z','io,phs']),('DNS queries',['tshark','-r',str(p),'-Y','dns.qry.name','-T','fields','-e','dns.qry.name']),('HTTP requests',['tshark','-r',str(p),'-Y','http.request','-T','fields','-e','http.request.method','-e','http.host','-e','http.request.uri'])]:
        _,text=run_tool(args,timeout=45,max_output=50000); out += ['',f'[{title}]',text or '(none)']
    return '\n'.join(out)

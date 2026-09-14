from pathlib import Path
from ..shared.tooling import run_tool, which
from ..shared.flags import find_flags
from ..crypto.analyzer import analyze
def summarize(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    if not which('tshark'): return 'tshark is not installed. Open the capture in Wireshark.'
    out=['PCAP SUMMARY','============']
    for title,args in [('protocol hierarchy',['tshark','-r',str(p),'-q','-z','io,phs']),('DNS queries',['tshark','-r',str(p),'-Y','dns.qry.name','-T','fields','-e','dns.qry.name']),('HTTP requests',['tshark','-r',str(p),'-Y','http.request','-T','fields','-e','http.request.method','-e','http.host','-e','http.request.uri'])]:
        _,text=run_tool(args,timeout=45,max_output=50000); out += ['',f'[{title}]',text or '(none)']
    _,payload=run_tool(['tshark','-r',str(p),'-Y','tcp','-T','fields','-e','data.text'],timeout=60,max_output=120000)
    text='\n'.join(x for x in payload.splitlines() if x)
    flags=find_flags(text)
    if flags: out += ['', '[possible flags in TCP payloads]']+[f'  {x}' for x in flags]
    # Analyze individual printable payload lines only; this avoids treating binary packets as text.
    decoded=[]
    for row in text.splitlines()[:300]:
        if 8<=len(row)<=10000:
            for result in analyze(row,max_depth=3,branch_limit=4,beam_width=4)[:1]:
                if find_flags(result.output): decoded.append(result.output)
    if decoded: out += ['', '[decoded payload clues]']+[f'  {x[:300]}' for x in dict.fromkeys(decoded)]
    out += ['', 'For file transfer reconstruction, use Wireshark File → Export Objects when the protocol hierarchy shows HTTP/SMB/FTP.']
    return '\n'.join(out)

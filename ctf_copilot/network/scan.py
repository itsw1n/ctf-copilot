import socket
from .resolve import resolve
def scan(host,ports=None,timeout=.4):
    ip=resolve(host)[0]; ports=ports or [21,22,23,25,53,80,110,143,443,445,3000,3306,5432,6379,8000,8080,8443]; out=[]
    for port in ports:
        try:
            fam=socket.AF_INET6 if ':' in ip else socket.AF_INET
            with socket.socket(fam,socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip,port))==0:
                    try: svc=socket.getservbyport(port,'tcp')
                    except OSError: svc='unknown'
                    out.append((port,svc))
        except OSError: pass
    return out

import socket
def connect(host,port,timeout=5.0):
    with socket.create_connection((host,port),timeout=timeout) as s:
        s.settimeout(1.0)
        try: data=s.recv(4096)
        except socket.timeout: data=b''
    return data.decode('utf-8','replace') or '(connected; no banner received)'

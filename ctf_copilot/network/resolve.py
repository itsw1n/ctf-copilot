import socket
def resolve(host): return list(dict.fromkeys(info[4][0] for info in socket.getaddrinfo(host,None)))

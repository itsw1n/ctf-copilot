ALPH=b'abcdefghijklmnopqrstuvwxyz'
def create(length: int) -> str:
    out=bytearray()
    for a in ALPH:
      for b in ALPH:
       for c in ALPH:
        out.extend((a,b,c))
        if len(out)>=length: return bytes(out[:length]).decode()
    return bytes(out[:length]).decode()
def offset(value: str, length: int=10000) -> int:
    pattern=create(length).encode()
    try:
        if value.startswith('0x'):
            n=int(value,16); width=8 if n>0xffffffff else 4; needle=n.to_bytes(width,'little')
        else: needle=value.encode()
    except Exception: needle=value.encode()
    return pattern.find(needle)

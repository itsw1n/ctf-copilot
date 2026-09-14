from __future__ import annotations
import base64, binascii, gzip, html, json, re, urllib.parse


def unwrap_python_bytes(value: str) -> str:
    raw=value.strip()
    m=re.fullmatch(r"b(['\"])(.*)\1", raw, re.S)
    return m.group(2) if m else raw


def decode_bytes(data: bytes) -> str:
    if data.startswith(b'\x1f\x8b'):
        try: data=gzip.decompress(data)
        except OSError: pass
    return data.decode('utf-8','replace')


def decode(kind: str, value: str) -> str:
    raw=unwrap_python_bytes(value)
    if kind in {'hex','base16'}:
        cleaned=re.sub(r'[\s:]','',raw)
        if len(cleaned)%2: raise ValueError('Hex input must contain an even number of digits.')
        return decode_bytes(bytes.fromhex(cleaned))
    if kind=='base64':
        cleaned=re.sub(r'\s+','',raw).replace('-','+').replace('_','/')
        cleaned += '='*((4-len(cleaned)%4)%4)
        return decode_bytes(base64.b64decode(cleaned,validate=True))
    if kind=='base32':
        cleaned=re.sub(r'\s+','',raw).upper(); cleaned += '='*((8-len(cleaned)%8)%8)
        return decode_bytes(base64.b32decode(cleaned,casefold=True))
    if kind=='base85': return decode_bytes(base64.b85decode(re.sub(r'\s+','',raw)))
    if kind=='ascii85': return decode_bytes(base64.a85decode(raw.strip(),adobe=raw.strip().startswith('<~')))
    if kind=='ascii':
        vals=[int(x) for x in re.findall(r'\d+',raw)]
        if not vals or any(x>255 for x in vals): raise ValueError('ASCII values must be 0..255.')
        return ''.join(chr(x) for x in vals)
    if kind=='binary':
        cleaned=re.sub(r'\s+','',raw)
        if not cleaned or not re.fullmatch(r'[01]+',cleaned) or len(cleaned)%8: raise ValueError('Binary length must be divisible by 8.')
        return ''.join(chr(int(cleaned[i:i+8],2)) for i in range(0,len(cleaned),8))
    if kind=='url': return urllib.parse.unquote_plus(raw)
    if kind=='html': return html.unescape(raw)
    raise ValueError(f'Unsupported encoding: {kind}')


def looks(kind: str, raw: str) -> bool:
    compact=re.sub(r'\s+','',raw)
    if kind=='hex':
        c=re.sub(r'[\s:]','',raw); return len(c)>=4 and len(c)%2==0 and bool(re.fullmatch(r'[0-9A-Fa-f]+',c))
    if kind=='base64': return len(compact)>=8 and len(compact)%4 in {0,2,3} and bool(re.fullmatch(r'[A-Za-z0-9+/=_-]+',compact))
    if kind=='base32':
        c=compact.upper(); return len(c)>=8 and bool(re.fullmatch(r'[A-Z2-7=]+',c)) and any(x in c for x in '234567=')
    if kind=='ascii': return bool(re.fullmatch(r'(?:\d{1,3}[\s,]+)+\d{1,3}',raw.strip()))
    if kind=='binary': return len(compact)>=16 and len(compact)%8==0 and bool(re.fullmatch(r'[01]+',compact))
    if kind=='url': return '%' in raw or bool(re.search(r'\+[A-Za-z0-9]',raw))
    if kind=='html': return bool(re.search(r'&(?:#\d+|#x[0-9a-fA-F]+|[A-Za-z]+);',raw))
    if kind=='ascii85': return raw.strip().startswith('<~') and raw.strip().endswith('~>')
    if kind=='base85': return len(raw)>=5 and bool(re.fullmatch(r'[\x21-\x75\s]+',raw))
    return False

from __future__ import annotations
import argparse, hashlib, json, re
from .analyzer import render
from .encodings.base import decode as decode_encoding
from .classical.caesar import all_shifts, atbash, rot13
from .classical.morse import decode as decode_morse
from .formats.jwt import decode as decode_jwt
from .xor.single_byte import candidates as xor_candidates
from .scoring import quality

def decode(kind,value,shift=None):
    if kind=='auto': return render(value)
    if kind in {'hex','base16','base64','base32','base85','ascii85','ascii','binary','url','html'}: return decode_encoding(kind,value)
    if kind=='rot13': return rot13(value)
    if kind=='atbash': return atbash(value)
    if kind=='morse': return decode_morse(value)
    if kind=='jwt': return json.dumps(decode_jwt(value),indent=2)
    if kind=='caesar':
        if shift is None: return '\n'.join(f'{n:2}: {text}' for n,text in all_shifts(value))
        from .classical.caesar import shift as caesar_shift
        return caesar_shift(value,shift)
    raise ValueError(kind)

def hash_ident(value: str) -> str:
    s=value.strip(); matches=[]
    if re.fullmatch(r'[0-9a-fA-F]{32}',s): matches.append('MD5 or NTLM (context needed)')
    if re.fullmatch(r'[0-9a-fA-F]{40}',s): matches.append('SHA-1')
    if re.fullmatch(r'[0-9a-fA-F]{64}',s): matches.append('SHA-256')
    if re.fullmatch(r'[0-9a-fA-F]{128}',s): matches.append('SHA-512')
    if s.startswith('$2'): matches.append('bcrypt')
    if s.startswith('$argon2'): matches.append('Argon2')
    return '\n'.join(['Likely hash type(s):']+[f'  - {m}' for m in matches]+['Hashes are one-way; identify/crack them rather than "decode" them.']) if matches else 'No common hash format recognized.'

def register(sub):
    q=sub.add_parser('crypto',help='Cryptography and encoding helpers'); sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('analyze',help='Rank likely encodings/ciphers and follow plausible layers'); z.add_argument('value'); z.set_defaults(fn=lambda a: print(render(a.value)))
    z=sp.add_parser('decode',help='Decode a specific supported format'); z.add_argument('value'); z.add_argument('--kind',default='auto',choices=['auto','base64','base32','base16','base85','ascii85','hex','ascii','binary','url','html','rot13','atbash','caesar','morse','jwt']); z.add_argument('--shift',type=int); z.set_defaults(fn=lambda a: print(decode(a.kind,a.value,a.shift)))
    z=sp.add_parser('caesar',help='Rank all Caesar shifts'); z.add_argument('value'); z.set_defaults(fn=lambda a: [print(f'{n:2} score={quality(t):.2f}  {t}') for n,t in sorted(all_shifts(a.value),key=lambda x:quality(x[1]),reverse=True)[:10]])
    z=sp.add_parser('xor',help='Try single-byte XOR candidates from hex'); z.add_argument('value'); z.set_defaults(fn=lambda a: [print(f'key=0x{k:02x} score={s:.2f} text={t[:160]}') for s,k,t in xor_candidates(a.value)])
    z=sp.add_parser('jwt',help='Decode JWT header/payload (does not verify signature)'); z.add_argument('token'); z.set_defaults(fn=lambda a: print(json.dumps(decode_jwt(a.token),indent=2)))
    z=sp.add_parser('hash',help='Identify common hash formats'); z.add_argument('value'); z.set_defaults(fn=lambda a: print(hash_ident(a.value)))

from __future__ import annotations
import json, re
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
    if re.fullmatch(r'[0-9a-fA-F]{32}',s): matches.append(('MD5 or NTLM','32 hexadecimal characters; context is required to distinguish them'))
    if re.fullmatch(r'[0-9a-fA-F]{40}',s): matches.append(('SHA-1','40 hexadecimal characters'))
    if re.fullmatch(r'[0-9a-fA-F]{64}',s): matches.append(('SHA-256','64 hexadecimal characters'))
    if re.fullmatch(r'[0-9a-fA-F]{128}',s): matches.append(('SHA-512','128 hexadecimal characters'))
    if s.startswith(('$2a$','$2b$','$2y$')): matches.append(('bcrypt','bcrypt modular crypt prefix'))
    if s.startswith('$argon2'): matches.append(('Argon2','Argon2 encoded-hash prefix'))
    if not matches: return 'No common hash format recognized. Hash type cannot always be determined from digest text alone.'
    out=['LIKELY HASH FAMILY','==================']
    for name,why in matches: out += [f'- {name}',f'  reason: {why}']
    out += ['','Purpose: identify the likely family so you can choose the correct auditing/cracking mode if the CTF requires recovering a guessable plaintext.','Hashes are one-way; they are tested against guesses, not directly decoded.']
    return '\n'.join(out)

def register(sub):
    q=sub.add_parser('crypto',help='Decode/identify encoded text, simple ciphers and hashes',description='Use for challenge text that looks encoded, shifted, XORed, tokenized, or hashed.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('analyze',help='Evidence-driven automatic detection and layered decoding',description='Best first crypto command. Detect strong structures first, explore several plausible decode chains, and rank meaningful outputs.'); z.add_argument('value'); z.set_defaults(fn=lambda a: print(render(a.value)))
    z=sp.add_parser('decode',help='Directly decode a known format/cipher',description='Use when you already know the type instead of asking the analyzer to guess.'); z.add_argument('value'); z.add_argument('--kind',default='auto',choices=['auto','base64','base32','base16','base85','ascii85','hex','ascii','binary','url','html','rot13','atbash','caesar','morse','jwt']); z.add_argument('--shift',type=int); z.set_defaults(fn=lambda a: print(decode(a.kind,a.value,a.shift)))
    z=sp.add_parser('caesar',help='Rank Caesar letter shifts',description='Use when alphabetic ciphertext may simply have each letter shifted by a fixed amount.'); z.add_argument('value'); z.set_defaults(fn=lambda a: [print(f'{n:2} score={quality(t):.2f}  {t}') for n,t in sorted(all_shifts(a.value),key=lambda x:quality(x[1]),reverse=True)[:10]])
    z=sp.add_parser('xor',help='Try single-byte XOR candidates from hex',description='Use when ciphertext is hex and the challenge hints at XOR or a single-byte key.'); z.add_argument('value'); z.set_defaults(fn=lambda a: [print(f'key=0x{k:02x} score={s:.2f} text={t[:160]}') for s,k,t in xor_candidates(a.value)])
    z=sp.add_parser('jwt',help='Decode JWT header/payload',description='Use on token strings with three dot-separated sections. Decoding does not verify the signature.'); z.add_argument('token'); z.set_defaults(fn=lambda a: print(json.dumps(decode_jwt(a.token),indent=2)))
    z=sp.add_parser('hash',help='Identify likely hash family',description='Use when you find a digest and need to know whether it resembles MD5/SHA/bcrypt/Argon2 before choosing a next tool.'); z.add_argument('value'); z.set_defaults(fn=lambda a: print(hash_ident(a.value)))

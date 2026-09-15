from __future__ import annotations
import json
from .auto import analyze_target
from .analyzer import render
from .encodings.base import decode as decode_encoding
from .classical.caesar import all_shifts, atbash, rot13
from .classical.morse import decode as decode_morse
from .formats.jwt import decode as decode_jwt
from .xor.single_byte import candidates as xor_candidates
from .scoring import quality
from .inspect import inspect_text, inspect_python
from .rsa_engine import render_rsa
from .repeating_xor import crack as repeating_xor
from .template import generate as generate_template
from .formats.hashes import render as render_hash
from .xor.engine import crib_drag, known_plaintext, single as xor_single
from .classical.vigenere import crack as crack_vigenere, decrypt as decrypt_vigenere
from .block import render as render_block

def decode(kind,value,shift=None):
    if kind=='auto': return render(value)
    if kind in {'hex','base16','base64','base32','base85','ascii85','ascii','binary','integer','url','html'}: return decode_encoding(kind,value)
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
    return render_hash(value)

def register(sub):
    q=sub.add_parser('crypto',help='Decode/identify encoded text, simple ciphers and hashes',description='Use for challenge text that looks encoded, shifted, XORed, tokenized, or hashed.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('analyze',help='Unified evidence-driven Crypto analysis',description='Best first crypto command. Accepts text or files, follows layered transforms, and delegates to bounded classical/XOR/RSA/block/source analyzers.'); z.add_argument('value'); z.add_argument('--input',action='append',default=[],help='Related value or file; repeat for multiple RSA/XOR inputs'); z.add_argument('--description',default='',help='Challenge prompt/hints'); z.add_argument('--flag-pattern'); z.add_argument('--known-plaintext',action='append',default=[]); z.add_argument('--max-depth',type=int,default=6,choices=range(1,9)); z.set_defaults(fn=lambda a: print(analyze_target(a.value,a.input,a.description,a.flag_pattern,a.known_plaintext,a.max_depth)))
    z=sp.add_parser('decode',help='Directly decode a known format/cipher',description='Use when you already know the type instead of asking the analyzer to guess.'); z.add_argument('value'); z.add_argument('--kind',default='auto',choices=['auto','base64','base32','base16','base85','ascii85','hex','ascii','binary','integer','url','html','rot13','atbash','caesar','morse','jwt']); z.add_argument('--shift',type=int); z.set_defaults(fn=lambda a: print(decode(a.kind,a.value,a.shift)))
    z=sp.add_parser('caesar',help='Rank Caesar letter shifts',description='Use when alphabetic ciphertext may simply have each letter shifted by a fixed amount.'); z.add_argument('value'); z.set_defaults(fn=lambda a: [print(f'{n:2} score={quality(t):.2f}  {t}') for n,t in sorted(all_shifts(a.value),key=lambda x:quality(x[1]),reverse=True)[:10]])
    z=sp.add_parser('xor',help='Try single-byte XOR candidates',description='Accepts hex, Base64, or raw ciphertext and tests all 256 one-byte keys.'); z.add_argument('value'); z.add_argument('--input-format',default='auto',choices=['auto','hex','base64','raw']); z.set_defaults(fn=lambda a: [print(f'key={row.key!r} score={row.score:.2f} text={row.plaintext[:240]}') for row in xor_single(a.value,a.input_format)])
    z=sp.add_parser('xor-repeat',help='Try short repeating-key XOR candidates from hex',description='Uses normalized Hamming distance and per-column frequency scoring; verify results manually.'); z.add_argument('value'); z.add_argument('--max-key-size',type=int,default=40,choices=range(2,41),help='Maximum key size to try, 2-40 (default 40); bounded by input length'); z.set_defaults(fn=_xor_repeat)
    z=sp.add_parser('jwt',help='Decode JWT header/payload',description='Use on token strings with three dot-separated sections. Decoding does not verify the signature.'); z.add_argument('token'); z.set_defaults(fn=lambda a: print(json.dumps(decode_jwt(a.token),indent=2)))
    z=sp.add_parser('hash',help='Identify likely hash family',description='Use when you find a digest and need to know whether it resembles MD5/SHA/bcrypt/Argon2 before choosing a next tool.'); z.add_argument('value'); z.set_defaults(fn=lambda a: print(hash_ident(a.value)))
    z=sp.add_parser('inspect',help='Find RSA/XOR/hash clues in text or Python source',description='Safely inspects crypto context; Python source is parsed but never executed.'); z.add_argument('value'); z.set_defaults(fn=lambda a: print(inspect_python(a.value) if __import__('pathlib').Path(a.value).suffix=='.py' else inspect_text(a.value)))
    z=sp.add_parser('xor-crib',help='Known-plaintext XOR and two-ciphertext crib dragging',description='Use when the challenge gives a likely plaintext fragment or two ciphertexts encrypted with the same keystream.'); z.add_argument('value'); z.add_argument('--crib',required=True); z.add_argument('--input'); z.add_argument('--input-format',default='auto',choices=['auto','hex','base64','raw']); z.set_defaults(fn=_xor_crib)
    z=sp.add_parser('vigenere',help='Decrypt with a known key or rank likely keys',description='Use when the challenge explicitly suggests Vigenere. Automatic candidates remain heuristic.'); z.add_argument('value'); z.add_argument('--key'); z.add_argument('--max-key-length',type=int,default=20,choices=range(2,21),help='Maximum key length to try, 2-20 (default 20)'); z.set_defaults(fn=_vigenere)
    z=sp.add_parser('rsa',help='Run bounded RSA weakness analysis',description='Accepts one or more n/e/c parameter files or values; supports supplied factors, low-e, shared-prime, common-modulus, broadcast, Wiener, and bounded factoring.'); z.add_argument('value'); z.add_argument('--input',action='append',default=[]); z.add_argument('--max-k',type=int,default=100000); z.set_defaults(fn=lambda a: print(render_rsa([a.value]+a.input,max(0,min(a.max_k,1000000)))))
    z=sp.add_parser('block',help='Inspect or decrypt AES/DES/3DES with supplied parameters',description='Detects repeated ECB blocks and decrypts only when the required key/IV/nonce is explicitly supplied.'); z.add_argument('ciphertext'); z.add_argument('--algorithm',default='aes',choices=['aes','des','3des']); z.add_argument('--mode',default='ecb',choices=['ecb','cbc','ctr']); z.add_argument('--key'); z.add_argument('--iv'); z.add_argument('--nonce'); z.add_argument('--input-format',default='auto',choices=['auto','hex','base64','raw']); z.add_argument('--key-format',default='auto',choices=['auto','hex','base64','raw']); z.set_defaults(fn=lambda a: print(render_block(a.ciphertext,a.algorithm,a.mode,a.key,a.iv,a.nonce,a.input_format,a.key_format)))
    z=sp.add_parser('template',help='Generate an editable solve.py scaffold from crypto source',description='Parses source without executing it and refuses to overwrite a script.'); z.add_argument('source'); z.add_argument('--output'); z.set_defaults(fn=lambda a: print(generate_template(a.source,a.output)))


def _xor_repeat(args):
    size = max(2, min(args.max_key_size, 40))
    rows = repeating_xor(args.value, size)
    if not rows:
        print('No usable hex ciphertext or candidate found.')
        return
    for score, key, text in rows:
        print(f'key={key!r} score={score:.2f} text={text[:240]}')


def _xor_crib(args):
    rows = crib_drag(args.value,args.input,args.crib,args.input_format) if args.input else known_plaintext(args.value,args.crib,args.input_format)
    if not rows:
        print('No usable XOR candidate found.')
        return
    for row in rows:
        print(f'offset={row.offset} score={row.score:.2f} key={row.key!r} text={row.plaintext[:300]}')


def _vigenere(args):
    if args.key:
        print(decrypt_vigenere(args.value,args.key))
        return
    rows=crack_vigenere(args.value,max(2,min(args.max_key_length,20)))
    if not rows:
        print('Not enough alphabetic text for reliable Vigenere key estimation.')
        return
    for row in rows:
        print(f'key={row.key} score={row.score:.2f} ic={row.key_length_score:.4f} text={row.plaintext[:400]}')

"""Safe static clue extraction for crypto challenge text and Python sources."""
from __future__ import annotations
import ast
import re
from pathlib import Path

RSA=re.compile(r'\b(?:n|e|d|p|q|c|ciphertext)\s*=\s*([0-9]{4,})', re.I)

def _hash_hint(value: str) -> str:
    s=value.strip()
    if re.fullmatch(r'[0-9a-fA-F]{32}',s): return 'MD5 or NTLM'
    if re.fullmatch(r'[0-9a-fA-F]{40}',s): return 'SHA-1'
    if re.fullmatch(r'[0-9a-fA-F]{64}',s): return 'SHA-256'
    if s.startswith(('$2a$','$2b$','$2y$')): return 'bcrypt'
    return ''

def inspect_text(text: str) -> str:
    rows=['CRYPTO CONTEXT INSPECTION','=========================']
    hashes=_hash_hint(text) if '\n' not in text and len(text.strip())<300 else ''
    if hashes: rows += ['',f'Likely hash family: {hashes}.','','Suggested next step: use the identified mode with John/Hashcat only if the plaintext is guessable.']
    labels=RSA.findall(text)
    if labels:
        rows += ['',f'RSA-like numeric values: {len(labels)}','Why it matters: supplied n/e/c/p/q values often reveal a weak RSA recipe.','Suggested next step: inspect whether p/q are leaked, n is prime/factorable, or e is unusually small.']
    if re.search(r'\b(?:xor|\^|exclusive or)\b',text,re.I): rows += ['', 'XOR clue detected.', 'Suggested next step: `ctf crypto xor <hex-ciphertext>` for single-byte XOR, or inspect supplied source for a repeating key.']
    if not labels and not hashes and len(rows)==2: rows.append('No high-confidence hash/RSA/XOR clue found; use `ctf crypto analyze` for encodings and classical ciphers.')
    return '\n'.join(rows)

def inspect_python(path: str) -> str:
    p=Path(path)
    if not p.is_file(): return f'Not a file: {p}'
    try: tree=ast.parse(p.read_text(encoding='utf-8',errors='replace'))
    except SyntaxError as exc: return f'Cannot parse Python source: {exc}'
    operations=[]; constants=[]; functions=[]
    for node in ast.walk(tree):
        if isinstance(node,ast.FunctionDef): functions.append(node.name)
        elif isinstance(node,ast.Assign) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,(str,int,bytes)):
            constants.append(f'{ast.unparse(node.targets[0])} = {node.value.value!r}')
        elif isinstance(node,ast.BinOp):
            op={ast.BitXor:'XOR',ast.Add:'addition',ast.Sub:'subtraction',ast.Mult:'multiplication',ast.Mod:'modulo',ast.Pow:'modular/exponentiation'}.get(type(node.op))
            if op: operations.append(op)
    out=['CRYPTO SOURCE INSPECTION (static; source was not executed)','===========================================================',f'Functions: {", ".join(functions[:30]) or "(none)"}',f'Constants: {", ".join(constants[:20]) or "(none)"}',f'Operations: {", ".join(dict.fromkeys(operations)) or "(none)"}']
    if operations: out += ['', 'Solve strategy: reverse reversible operations in reverse order. XOR reverses with the same key; addition/subtraction invert each other; multiplication needs a known factor or modular inverse.']
    return '\n'.join(out)

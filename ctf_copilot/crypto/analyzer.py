from __future__ import annotations
import json, re
from collections import deque
from .models import Candidate, PathResult
from .scoring import quality, confidence, has_known_flag
from .encodings.base import decode as decode_encoding, looks as looks_encoding, unwrap_python_bytes
from .classical.caesar import all_shifts, atbash, rot13
from .classical.morse import decode as decode_morse, looks as looks_morse
from .formats.jwt import looks as looks_jwt, decode as decode_jwt
from ..shared.flags import find_flags

ENCODINGS=[('hex',.65),('base64',.35),('base32',.45),('ascii',.65),('binary',.8),('url',.45),('html',.55),('ascii85',.55),('base85',-.35)]

def _candidate(kind,output,reason,structural=0.0,parameter=None):
    score=quality(output)+structural
    return Candidate(kind,output,score,confidence(score),reason,parameter)

def detect_candidates(value: str, include_classics: bool=True) -> list[Candidate]:
    raw=unwrap_python_bytes(value); rows=[]
    for kind,bonus in ENCODINGS:
        if not looks_encoding(kind,raw): continue
        try:
            out=decode_encoding(kind,raw)
            if out and out!=raw: rows.append(_candidate(kind,out,f'{kind} structural pattern',bonus))
        except Exception: pass
    if looks_morse(raw):
        try: rows.append(_candidate('morse',decode_morse(raw),'Morse dot/dash pattern',.75))
        except Exception: pass
    if looks_jwt(raw):
        try: rows.append(_candidate('jwt',json.dumps(decode_jwt(raw),ensure_ascii=False),'three JWT-like segments',.9))
        except Exception: pass
    if include_classics and sum(c.isalpha() for c in raw)>=6:
        ab=atbash(raw); rows.append(_candidate('atbash',ab,'alphabetic text tested as Atbash',-.3))
        for amount,out in all_shifts(raw):
            if quality(out)>=1.2 or has_known_flag(out): rows.append(_candidate('caesar',out,'tested all Caesar rotations',-.15,f'shift=-{amount}'))
        r=rot13(raw)
        if quality(r)>=2.0: rows.append(_candidate('rot13',r,'ROT13 transformation',-.1))
    best={}
    for row in rows:
        key=(row.kind,row.parameter,row.output)
        if key not in best or row.score>best[key].score: best[key]=row
    return sorted(best.values(),key=lambda x:(has_known_flag(x.output),x.score),reverse=True)

def analyze(value: str, max_depth: int=4, branch_limit: int=6) -> list[PathResult]:
    start=unwrap_python_bytes(value); q=deque([(start,tuple())]); seen={start}; finals=[]
    while q:
        current,chain=q.popleft(); cands=detect_candidates(current)[:branch_limit]
        if not cands:
            if chain: finals.append(PathResult(chain,current,quality(current)))
            continue
        for cand in cands:
            if cand.output in seen: continue
            seen.add(cand.output); new_chain=chain+(cand,); score=quality(cand.output)+sum(s.score for s in new_chain)*.08
            finals.append(PathResult(new_chain,cand.output,score))
            if len(new_chain)<max_depth and (cand.confidence>=.12 or cand.kind in {'hex','base64','base32','base85','ascii85','ascii','binary','url','html','morse','jwt'}) and not has_known_flag(cand.output): q.append((cand.output,new_chain))
    dedup={}
    for r in finals:
        key=(r.output,tuple((x.kind,x.parameter) for x in r.chain))
        if key not in dedup or r.score>dedup[key].score: dedup[key]=r
    return sorted(dedup.values(),key=lambda r:(has_known_flag(r.output),r.score),reverse=True)[:10]

def render(value: str) -> str:
    results=analyze(value)
    if not results: return 'No strong supported encoding/cipher candidate detected.'
    lines=['CRYPTO ANALYSIS','===============']
    for i,r in enumerate(results[:5],1):
        last=r.chain[-1]; chain=' -> '.join(f'{x.kind}({x.parameter})' if x.parameter else x.kind for x in r.chain)
        lines += ['',f'[{i}] {last.kind}'+(f' {last.parameter}' if last.parameter else ''),f'    confidence: {int(last.confidence*100)}%',f'    chain: {chain}',f'    reason: {last.reason}',f'    output: {r.output}']
    best=results[0]
    lines += ['', 'Best candidate:' if (best.chain[-1].confidence>=.55 or has_known_flag(best.output)) else 'Best candidate is uncertain; inspect manually.', best.output]
    return '\n'.join(lines)

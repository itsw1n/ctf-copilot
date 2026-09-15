from __future__ import annotations
import json
from .models import Candidate, PathResult
from .normalization import parse_bytes, readable
from .scoring import quality, confidence, has_known_flag, structural, step_score, SPECULATIVE, printable_ratio
from .encodings.base import decode as decode_encoding, looks as looks_encoding, unwrap_python_bytes
from .classical.caesar import all_shifts, atbash, rot13
from .classical.morse import decode as decode_morse, looks as looks_morse
from .formats.jwt import looks as looks_jwt, decode as decode_jwt

STRONG_ENCODINGS=('hex','binary','url','html','base32','base64','ascii85','ascii','integer','base85')

def _cand(kind: str, output: str, reason: str, parameter: str|None=None) -> Candidate:
    st=structural(kind)
    score=step_score(kind,output)
    return Candidate(kind,output,score,confidence(score),reason,parameter,st,kind in SPECULATIVE)

def detect_candidates(value: str, include_classics: bool=True) -> list[Candidate]:
    raw=unwrap_python_bytes(value)
    rows=[]
    for kind in STRONG_ENCODINGS:
        if not looks_encoding(kind,raw):
            continue
        try:
            out=decode_encoding(kind,raw)
            if out and out != raw:
                # Text analyzer: suppress structurally valid decodes that turn into mostly binary/invalid UTF-8 noise.
                # Those are still available through explicit `decode --kind ...` and file-forensics workflows.
                if ('�' in out and not has_known_flag(out)) or printable_ratio(out) < .82:
                    continue
                rows.append(_cand(kind,out,f'input matches {kind} structure and decoded successfully'))
        except Exception:
            pass
    if looks_morse(raw):
        try: rows.append(_cand('morse',decode_morse(raw),'dot/dash token structure strongly matches Morse'))
        except Exception: pass
    # Byte-safe beam: ensure integer kind participates even for short
    # pure-decimal inputs (parse_bytes maps "65" -> b"A"). Use readable
    # to avoid replacement-character damage; drop binary noise.
    stripped = raw.strip()
    if stripped.isdigit() and not any(row.kind == "integer" for row in rows):
        try:
            raw_bytes = parse_bytes(stripped, "auto")
            text = readable(raw_bytes)
            if text and text != raw and "�" not in text and printable_ratio(text) >= 0.82:
                rows.append(_cand("integer", text, "input matches integer structure and decoded successfully"))
        except Exception:
            pass
    if looks_jwt(raw):
        try: rows.append(_cand('jwt',json.dumps(decode_jwt(raw),ensure_ascii=False,sort_keys=True),'three JWT-like segments decoded successfully'))
        except Exception: pass

    # Classical ciphers are heuristic: only promote a shift when plaintext quality improves
    # materially over the original. This prevents Base64-shaped text being flooded by Caesar.
    if include_classics and sum(c.isalpha() for c in raw) >= 6:
        baseline=quality(raw)
        r=rot13(raw)
        if quality(r) >= baseline + .65 or has_known_flag(r):
            rows.append(_cand('rot13',r,'ROT13 produced meaningfully stronger plaintext'))
        ab=atbash(raw)
        if quality(ab) >= baseline + .85 or has_known_flag(ab):
            rows.append(_cand('atbash',ab,'Atbash produced meaningfully stronger plaintext'))
        caesar_rows=[]
        for amount,out in all_shifts(raw):
            improvement=quality(out)-baseline
            if improvement >= .8 or has_known_flag(out):
                c=_cand('caesar',out,f'Caesar shift improved plaintext quality by {improvement:.2f}',f'shift=-{amount}')
                caesar_rows.append(c)
        rows.extend(sorted(caesar_rows,key=lambda c:c.score,reverse=True)[:4])

    # Deduplicate exact transformations.
    best={}
    for row in rows:
        key=(row.kind,row.parameter,row.output)
        if key not in best or row.score>best[key].score:
            best[key]=row
    return sorted(best.values(),key=lambda c:(has_known_flag(c.output),c.structural_confidence,c.score),reverse=True)

def _path_score(chain: tuple[Candidate,...], output: str) -> float:
    total=quality(output)
    for depth,c in enumerate(chain,1):
        total += c.structural_confidence*2.3
        total += min(c.score,7.0)*.12
        total -= .16*(depth-1)              # depth penalty
        if c.speculative: total -= .45       # speculative branch penalty
    if has_known_flag(output): total += 6.0
    return total

def analyze(value: str, max_depth: int=6, branch_limit: int=8, beam_width: int=10) -> list[PathResult]:
    max_depth = max(1, min(max_depth, 8))
    start=unwrap_python_bytes(value)
    frontier=[(start,tuple())]
    seen_depth={(start,0)}
    finals=[]
    for depth in range(max_depth):
        expanded=[]
        for current,chain in frontier:
            cands=detect_candidates(current)
            if not cands and chain:
                finals.append(PathResult(chain,current,_path_score(chain,current)))
            for cand in cands[:branch_limit]:
                new_chain=chain+(cand,)
                result=PathResult(new_chain,cand.output,_path_score(new_chain,cand.output))
                finals.append(result)
                if has_known_flag(cand.output):
                    continue
                state=(cand.output,depth+1)
                if state in seen_depth:
                    continue
                seen_depth.add(state)
                expanded.append((cand.output,new_chain,result.score))
        if not expanded:
            break
        # Beam search: preserve several best alternatives, favoring structural evidence.
        expanded.sort(key=lambda x:x[2],reverse=True)
        frontier=[(out,chain) for out,chain,_ in expanded[:beam_width]]

    dedup={}
    for r in finals:
        key=(r.output,tuple((x.kind,x.parameter) for x in r.chain))
        if key not in dedup or r.score>dedup[key].score:
            dedup[key]=r
    return sorted(dedup.values(),key=lambda r:(has_known_flag(r.output),r.score),reverse=True)[:12]

def render(value: str) -> str:
    results=analyze(value)
    if not results:
        return 'No strong supported encoding/cipher candidate detected. Try a manual decoder or inspect the challenge context.'
    lines=['CRYPTO ANALYSIS','===============']
    for i,r in enumerate(results[:5],1):
        last=r.chain[-1]
        chain=' -> '.join(f'{x.kind}({x.parameter})' if x.parameter else x.kind for x in r.chain)
        path_conf=min(.99,max(.01, confidence(r.score)))
        lines += ['',f'[{i}] {chain}',f'    confidence: {int(path_conf*100)}%',f'    reason: {last.reason}',f'    output: {r.output}']
    best=results[0]
    best_conf=confidence(best.score)
    lines += ['', 'Best candidate:' if (best_conf>=.60 or has_known_flag(best.output)) else 'Best candidate is uncertain; inspect manually.', best.output]
    weak=sum(1 for r in results[5:] if r.chain[-1].speculative)
    if weak: lines += ['',f'Weak speculative candidates hidden from the top view: {weak}']
    return '\n'.join(lines)

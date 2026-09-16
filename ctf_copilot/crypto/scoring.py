from __future__ import annotations
import math, string

COMMON_WORDS=(
    'the','and','this','that','flag','ctf','picoctf','secret','password','crypto',
    'caesar','decode','encoded','key','http','hello','admin','user','correct','wrong',
    'login','token','message','challenge','answer','success'
)
# Compatibility aliases: delegate to shared/flags.py (single source of truth).
# New code must use has_known_flag()/looks_flag_like() so configured prefixes
# from <repo-root>/config.toml are honored.
from ..shared.flags import FLAG_LIKE, KNOWN_FLAG, has_known_flag, looks_flag_like

# Structural evidence is intentionally separated from plaintext quality.
# A valid Base64/Hex shape is evidence that a transformation is appropriate;
# readable English is evidence that the resulting plaintext is useful.
STRUCTURAL_WEIGHT={
    'gzip': 1.00, 'jwt': .98, 'binary': .96, 'morse': .94, 'hex': .92,
    'url': .88, 'html': .86, 'base32': .82, 'base64': .80,
    'ascii85': .76, 'ascii': .74, 'base85': .58,
    'integer': .78,
    'rot13': .30, 'atbash': .24, 'caesar': .18, 'xor': .14,
}
SPECULATIVE={'caesar','rot13','atbash','xor'}

def printable_ratio(text: str) -> float:
    if not text: return 0.0
    return sum(c in string.printable or c in '\n\r\t' for c in text)/len(text)

def language_score(text: str) -> float:
    if not text: return -5.0
    low=text.lower()
    words=sum(1 for w in COMMON_WORDS if w in low)
    letters=sum(c.isalpha() for c in text)
    spaces=text.count(' ')
    alpha_ratio=letters/max(1,len(text))
    score=min(words,8)*.48 + min(alpha_ratio,.9)*.35
    if spaces and letters: score += min(spaces/max(1,len(text)),.2)*.8
    return score

def quality(text: str) -> float:
    if not text: return -10.0
    pr=printable_ratio(text)
    replacement=text.count('�')/len(text)
    control=sum(ord(c)<32 and c not in '\n\r\t' for c in text)/len(text)
    score=pr*1.25-replacement*4-control*3+language_score(text)
    if has_known_flag(text): score += 5.0
    elif looks_flag_like(text): score += .65
    # Numeric plaintext is legitimate in CTFs; don't punish it simply for lacking letters.
    if text.strip().isdigit(): score += .35
    # JSON-like results are often useful after JWT/Base64 layers.
    s=text.strip()
    if (s.startswith('{') and s.endswith('}')) or (s.startswith('[') and s.endswith(']')): score += .35
    return score

def structural(kind: str) -> float:
    return STRUCTURAL_WEIGHT.get(kind,.1)

def step_score(kind: str, output: str) -> float:
    base=structural(kind)*3.0 + quality(output)
    if kind in SPECULATIVE: base -= .7
    return base

def confidence(score: float) -> float:
    raw=1/(1+math.exp(-(score-3.2)*1.05))
    return round(min(.99,max(.01,raw)),2)

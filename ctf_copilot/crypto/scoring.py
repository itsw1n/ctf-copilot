from __future__ import annotations
import math, re, string
COMMON=('the','and','this','that','flag','ctf','picoctf','secret','password','crypto','caesar','decode','encoded','key','http','hello','admin','user')
KNOWN_FLAG=re.compile(r'(?i)(?:flag|ctf|picoCTF|HTB|THM)\{')

def has_known_flag(text: str) -> bool:
    return bool(KNOWN_FLAG.search(text))

def quality(text: str) -> float:
    if not text: return -10.0
    printable=sum(c in string.printable or c in '\n\r\t' for c in text)/len(text)
    replacement=text.count('�')/len(text)
    control=sum(ord(c)<32 and c not in '\n\r\t' for c in text)/len(text)
    low=text.lower(); words=sum(low.count(w) for w in COMMON)
    known=has_known_flag(text)
    brace=0.15 if re.search(r'[A-Za-z0-9_-]{2,24}\{[^{}]+\}',text) else 0.0
    alpha=sum(c.isalpha() for c in text)/len(text)
    # Generic printable text is deliberately modest; strong confidence needs language/known-flag evidence.
    return printable*1.4-replacement*4-control*3+min(words,6)*0.45+(5.0 if known else 0.0)+brace+min(alpha,.85)*.15

def confidence(score: float) -> float:
    raw=1/(1+math.exp(-(score-3.8)*1.25))
    return round(min(.99,max(.01,raw)),2)

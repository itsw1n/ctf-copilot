import re
def patterns(prefix=None):
    rows=[re.compile(r"\b(?:flag|ctf|picoCTF|HTB|THM)\{[^{}\r\n]{1,300}\}",re.I),re.compile(r"\b[A-Za-z0-9_-]{2,24}\{[^{}\r\n]{1,300}\}")]
    if prefix: rows.insert(0,re.compile(re.escape(prefix)+r'\{[^{}\r\n]{1,300}\}',re.I))
    return rows

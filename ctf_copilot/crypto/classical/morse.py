MORSE={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'}

def decode(value: str) -> str:
    import re
    return ' '.join(''.join(MORSE.get(tok,'?') for tok in word.split()) for word in re.split(r'\s*/\s*',value.strip()))

def looks(value: str) -> bool:
    import re
    s=value.strip(); return len(s)>=3 and bool(re.fullmatch(r'[.\-/\s]+',s)) and ('.' in s or '-' in s)

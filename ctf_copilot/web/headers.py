SECURITY_HEADERS=['content-security-policy','x-content-type-options','referrer-policy','permissions-policy']
def audit(headers: dict[str,str], https: bool=False) -> list[str]:
    low={k.lower():v for k,v in headers.items()}; rows=[]
    for name in SECURITY_HEADERS: rows.append(f'{name}: {"present" if name in low else "missing"}')
    if https: rows.append(f'strict-transport-security: {"present" if "strict-transport-security" in low else "missing"}')
    return rows

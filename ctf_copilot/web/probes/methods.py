from .common import request
def probe(url):
    out=[]
    for m in ('GET','HEAD','OPTIONS','POST','PUT','DELETE'):
        try: out.append(f'{m:<7} {request(url,m)[0]}')
        except Exception as e: out.append(f'{m:<7} error: {e.__class__.__name__}')
    return out

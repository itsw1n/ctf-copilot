from ..shared.flags import find_flags
from ..shared.tooling import run_tool, which
def show(path):
    if not which('strings'): raise SystemExit('strings is not installed.')
    text=run_tool(['strings','-a','-n','4',path],timeout=30,max_output=120000)[1]; keys=('flag','password','correct','wrong','secret','admin','success','fail','key')
    print('\n'.join(x for x in text.splitlines() if any(k in x.lower() for k in keys)) or 'No obvious high-signal strings found.')
    flags=find_flags(text)
    if flags: print('\nFlag-like strings (unconfirmed):\n'+'\n'.join(f'  {f}' for f in flags[:20]))

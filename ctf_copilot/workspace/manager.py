from pathlib import Path
import os
def base(): return Path(os.environ.get('CTF_COPILOT_HOME', str(Path.home()/'.ctf-copilot')))/'workspaces'
def new(name):
    root=base()/name
    for part in ('files','extracted','scripts','output','evidence'): (root/part).mkdir(parents=True,exist_ok=True)
    if not (root/'notes.md').exists(): (root/'notes.md').write_text(f'# {name}\n\n')
    return root
def note(name,text):
    root=new(name)
    with (root/'notes.md').open('a',encoding='utf-8') as f: f.write(text+'\n')
    return root/'notes.md'
def list_all():
    root=base(); return [] if not root.exists() else sorted(x.name for x in root.iterdir() if x.is_dir())
def info(name):
    root=base()/name
    if not root.exists(): return f'Workspace not found: {name}'
    return '\n'.join([f'Workspace: {root}',f'Notes: {root/"notes.md"}',f'Files: {sum(1 for x in root.rglob("*") if x.is_file())}'])

def save_report(name, report):
    root = new(name)
    return report.save(root / 'evidence' / 'solve-report.json')

def load_report(name):
    import json
    p = base()/name/'evidence'/'solve-report.json'
    return json.loads(p.read_text(encoding='utf-8')) if p.exists() else None

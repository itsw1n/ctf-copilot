from .manager import new,note,list_all,info,flatten
def register(sub):
    q=sub.add_parser('workspace',help='Organize challenge files and notes',description='Use during competition to keep evidence, extracted files and discoveries grouped per challenge.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('new',help='Create challenge workspace',description='Creates one flat challenge folder plus notes.md.'); z.add_argument('name'); z.set_defaults(fn=lambda a: print(new(a.name)))
    z=sp.add_parser('note',help='Append a finding to notes',description='Save a clue/decision so you do not forget it while switching challenges.'); z.add_argument('name'); z.add_argument('note'); z.set_defaults(fn=lambda a: print(note(a.name,a.note)))
    z=sp.add_parser('list',help='List challenge workspaces',description='See all workspaces stored by CTF Copilot.'); z.set_defaults(fn=lambda a:[print(x) for x in list_all()] if list_all() else print('No workspaces yet.'))
    z=sp.add_parser('info',help='Show workspace summary',description='Show location, notes path and file count for a challenge workspace.'); z.add_argument('name'); z.set_defaults(fn=lambda a: print(info(a.name)))
    z=sp.add_parser('flatten',help='Flatten an older nested workspace',description='Moves files from legacy files/extracted/scripts/output/evidence folders into the workspace root.'); z.add_argument('name'); z.set_defaults(fn=lambda a: print(flatten(a.name)))

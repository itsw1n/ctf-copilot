from .manager import new,note,list_all,info
def register(sub):
    q=sub.add_parser('workspace',help='Challenge organization and notes'); sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('new'); z.add_argument('name'); z.set_defaults(fn=lambda a: print(new(a.name)))
    z=sp.add_parser('note'); z.add_argument('name'); z.add_argument('note'); z.set_defaults(fn=lambda a: print(note(a.name,a.note)))
    z=sp.add_parser('list'); z.set_defaults(fn=lambda a:[print(x) for x in list_all()] if list_all() else print('No workspaces yet.'))
    z=sp.add_parser('info'); z.add_argument('name'); z.set_defaults(fn=lambda a: print(info(a.name)))

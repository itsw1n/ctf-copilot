from .morse import decode
from .conversions import convert
from .timestamps import convert as timestamp
def register(sub):
    q=sub.add_parser('misc',help='Small conversion helpers',description='Use for simple transformations that do not need full crypto analysis.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('morse',help='Decode Morse code',description='Use on dot/dash-separated Morse text.'); z.add_argument('value'); z.set_defaults(fn=lambda a: print(decode(a.value)))
    z=sp.add_parser('base',help='Convert numbers between bases',description='Convert a known numeric value between binary/octal/decimal/hex.'); z.add_argument('value'); z.add_argument('--from-base',type=int,choices=[2,8,10,16],required=True); z.add_argument('--to-base',type=int,choices=[2,8,10,16],required=True); z.set_defaults(fn=lambda a: print(convert(a.value,a.from_base,a.to_base)))
    z=sp.add_parser('timestamp',help='Convert Unix timestamp',description='Use when a challenge gives an epoch timestamp and you need a readable date/time.'); z.add_argument('value'); z.set_defaults(fn=lambda a: print(timestamp(a.value)))

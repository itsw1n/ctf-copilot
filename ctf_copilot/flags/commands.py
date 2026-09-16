from ..shared.flags import emit_flag_config_warnings_once
from .scanner import scan
def register(sub):
    q=sub.add_parser('flags',help='Search evidence for flag-like strings',description='Use after extracting/downloading many files so you do not miss an already-present flag.')
    sp=q.add_subparsers(dest='action',required=True)
    z=sp.add_parser('scan',help='Recursively scan text/binary-readable content',description='Search a file, directory, or text for common CTF flag patterns; use --prefix for event-specific flags.'); z.add_argument('value'); z.add_argument('--prefix'); z.set_defaults(fn=lambda a:_scan(a))
def _scan(a):
    emit_flag_config_warnings_once()
    rows=scan(a.value,a.prefix)
    if not rows: print('No flag-like strings found.')
    else:
        for path,flag in rows: print(f'{path}: {flag}')

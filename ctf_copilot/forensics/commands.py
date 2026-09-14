from pathlib import Path
from .triage import triage
from .metadata import show as metadata
from .archive import inspect as archive
from .pcap import summarize as pcap
from .stego import inspect as stego
from ..shared.tooling import run_tool, which
def register(sub):
    q=sub.add_parser('forensics',help='Files, metadata, stego, archives and PCAP triage'); sp=q.add_subparsers(dest='action',required=True)
    for name,help_,fn in [('triage','Automatic first-pass file triage',lambda a: print(triage(a.path))),('metadata','Show ExifTool metadata',lambda a: metadata(a.path)),('archive','Inspect ZIP/archive clues',lambda a: print(archive(a.path))),('pcap','Summarize PCAP with tshark',lambda a: print(pcap(a.path))),('stego','Run type-appropriate stego checks',lambda a: print(stego(a.path)))]:
        z=sp.add_parser(name,help=help_); z.add_argument('path'); z.set_defaults(fn=fn)
    z=sp.add_parser('strings',help='Extract printable strings'); z.add_argument('path'); z.set_defaults(fn=lambda a:_strings(a.path))
    z=sp.add_parser('hex',help='Show first bytes as hex'); z.add_argument('path'); z.add_argument('--bytes',type=int,default=256); z.set_defaults(fn=lambda a: print(Path(a.path).read_bytes()[:max(1,min(a.bytes,4096))].hex(' ')))
def _strings(path):
    if not which('strings'): raise SystemExit('strings is not installed.')
    print(run_tool(['strings','-a','-n','4',path],timeout=30,max_output=120000)[1])

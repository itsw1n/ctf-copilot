from pathlib import Path
from .triage import triage
from .metadata import show as metadata
from .archive import inspect as archive
from .recurse import inspect as recurse
from .pcap import summarize as pcap
from .stego import inspect as stego
from ..shared.tooling import run_tool, which

def register(sub):
    q=sub.add_parser('forensics',help='Investigate files, images, archives and PCAP evidence',description='Use for challenges where the flag/clue may be hidden in a file, metadata, archive, image/audio stego, or packet capture.')
    sp=q.add_subparsers(dest='action',required=True)
    defs=[
      ('triage','Unknown file? Run type/metadata/strings/embedded-data checks first.','Automatic first-pass file triage',lambda a: print(triage(a.path))),
      ('metadata','Use when EXIF/comments/GPS/software fields may contain clues.','Show ExifTool metadata',lambda a: metadata(a.path)),
      ('archive','Use before extraction to inspect entries, encryption, and nesting clues.','Inspect ZIP/archive clues',lambda a: print(archive(a.path))),
      ('recurse','Use on nested ZIP challenges; safely follows nested readable data/flags.','Safely inspect nested ZIP layers',lambda a: print(recurse(a.path))),
      ('pcap','Use for .pcap/.pcapng challenges to summarize protocols/DNS/HTTP.','Summarize PCAP with tshark',lambda a: print(pcap(a.path))),
      ('stego','Use when an image/audio file may hide data beyond visible content.','Run type-appropriate stego checks',lambda a: print(stego(a.path))),
    ]
    for name,desc,help_,fn in defs:
        z=sp.add_parser(name,help=help_,description=desc); z.add_argument('path'); z.set_defaults(fn=fn)
    z=sp.add_parser('strings',help='Extract printable strings',description='Use when a binary/file may contain readable passwords, URLs, flags, or clues.'); z.add_argument('path'); z.set_defaults(fn=lambda a:_strings(a.path))
    z=sp.add_parser('hex',help='Show first bytes as hex',description='Use to inspect file signatures/magic bytes manually.'); z.add_argument('path'); z.add_argument('--bytes',type=int,default=256); z.set_defaults(fn=lambda a: print(Path(a.path).read_bytes()[:max(1,min(a.bytes,4096))].hex(' ')))

def _strings(path):
    if not which('strings'): raise SystemExit('strings is not installed.')
    print(run_tool(['strings','-a','-n','4',path],timeout=30,max_output=120000)[1])

from pathlib import Path
from .pipeline import triage_file
from ..analysis.budget import AnalysisBudget
from .metadata import show as metadata
from .archive import inspect as archive
from .recurse import inspect as recurse
from .pcap import summarize as pcap
from .stego import inspect as stego
from .evidence import inspect as evidence
from ..shared.tooling import run_tool, which

def register(sub):
    q=sub.add_parser('forensics',help='Investigate files, images, archives and PCAP evidence',description='Use for challenges where the flag/clue may be hidden in a file, metadata, archive, image/audio stego, or packet capture.')
    sp=q.add_subparsers(dest='action',required=True)
    defs=[
      ('triage','Unknown file? Run type/metadata/strings/embedded-data checks first.','Automatic first-pass file triage',lambda a: _triage(a.path, getattr(a, 'workspace', None), getattr(a, 'budget', 'balanced'))),
      ('metadata','Use when EXIF/comments/GPS/software fields may contain clues.','Show metadata and document clues',lambda a: print(metadata(a.path))),
      ('archive','Use before extraction to inspect entries, encryption, and nesting clues.','Inspect archive clues',lambda a: print(archive(a.path, a.password, a.crack, a.extract))),
      ('recurse','Use on nested archive challenges; safely follows readable data/flags.','Safely inspect nested archive layers',lambda a: print(recurse(a.path))),
      ('pcap','Use for .pcap/.pcapng challenges to summarize protocols/DNS/HTTP.','Summarize PCAP with tshark',lambda a: print(pcap(a.path))),
      ('stego','Use when an image/audio file may hide data beyond visible content.','Run type-appropriate stego checks',lambda a: print(stego(a.path, a.all, a.extract))),
    ]
    for name,desc,help_,fn in defs:
        z=sp.add_parser(name,help=help_,description=desc); z.add_argument('path');
        if name=='triage':
            z.add_argument('--workspace',default=None,help='Workspace dir for extracted artifacts')
            z.add_argument('--budget',default='balanced',choices=['fast','balanced','deep'],help='Analysis budget profile')
        if name=='archive':
            z.add_argument('--password',action='append',default=[],help='Password candidate from challenge clues')
            z.add_argument('--crack',action='store_true',help='Show controlled cracking handoff')
            z.add_argument('--extract',help='Extract safely into this directory after a successful password')
        if name=='stego':
            z.add_argument('--all',action='store_true',help='Run all applicable checks')
            z.add_argument('--extract',help='Extract binwalk artifacts into this directory')
        z.set_defaults(fn=fn)
    z=sp.add_parser('strings',help='Extract printable strings',description='Use when a binary/file may contain readable passwords, URLs, flags, or clues.'); z.add_argument('path'); z.set_defaults(fn=lambda a:_strings(a.path))
    z=sp.add_parser('hex',help='Show first bytes as hex',description='Use to inspect file signatures/magic bytes manually.'); z.add_argument('path'); z.add_argument('--bytes',type=int,default=256); z.set_defaults(fn=lambda a: print(Path(a.path).read_bytes()[:max(1,min(a.bytes,4096))].hex(' ')))
    z=sp.add_parser('evidence',help='Correlate magic bytes, embedded data and clue paths',description='Explains signature mismatches, embedded files, encoded text, and relevant next tools.'); z.add_argument('path'); z.set_defaults(fn=lambda a: print(evidence(a.path)))

def _persist_to_workspace(path, findings, artifacts, workspace) -> tuple[list, object | None]:
    """Copy triage artifacts flat into workspace dir + save solve-report.json.

    Returns (persisted_artifacts, report_path). Collision-safe artifact-XXX
    names mirror shared/archives._copy_to_workspace. Parent links preserved
    via Artifact.source_artifact.
    """
    import re
    import shutil
    import hashlib
    from ..analysis.models import Artifact, SolveReport
    from ..analysis.runner import artifact_for
    ws = Path(str(workspace))
    ws.mkdir(parents=True, exist_ok=True)

    def _sha(p: Path) -> str | None:
        try:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(1048576), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def _find_same(digest: str | None) -> Path | None:
        if not digest:
            return None
        try:
            for f in ws.iterdir():
                if f.is_file() and f.name.startswith("artifact-"):
                    if _sha(f) == digest:
                        return f
        except OSError:
            pass
        return None

    persisted: list[Artifact] = []
    index = 0
    for art in (artifacts or []):
        try:
            src = Path(art.path)
        except Exception:
            continue
        if not src.is_file() or src.is_symlink():
            continue
        # skip copying the workspace dir into itself
        try:
            if ws.resolve() in [src.resolve(), *src.resolve().parents] or src.resolve().parent == ws.resolve() and src.name.startswith("artifact-"):
                continue
        except Exception:
            pass
        # idempotent rescan: reuse existing identical artifact instead of duplicating
        try:
            digest = _sha(src)
            dup = _find_same(digest)
            if dup is not None:
                try:
                    new_art = artifact_for(str(dup), kind=getattr(art, "kind", "extracted"),
                                           source=getattr(art, "source", "triage"),
                                           depth=getattr(art, "depth", 0) or 0)
                    new_art.source_artifact = getattr(art, "source_artifact", "") or str(path)
                    persisted.append(new_art)
                except Exception:
                    pass
                continue
        except Exception:
            pass
        index += 1
        safe_base = re.sub(r"[^A-Za-z0-9._-]", "_", src.name) or "file"
        dest = ws / f"artifact-{index:03d}-{safe_base}"
        n = 0
        while dest.exists():
            # same content already at candidate name -> reuse, no duplication
            try:
                if _sha(dest) == _sha(src):
                    break
            except Exception:
                pass
            n += 1
            dest = ws / f"artifact-{index:03d}-{n}-{safe_base}"
        if dest.exists():
            try:
                if _sha(dest) == _sha(src):
                    try:
                        new_art = artifact_for(str(dest), kind=getattr(art, "kind", "extracted"),
                                               source=getattr(art, "source", "triage"),
                                               depth=getattr(art, "depth", 0) or 0)
                        new_art.source_artifact = getattr(art, "source_artifact", "") or str(path)
                        persisted.append(new_art)
                    except Exception:
                        pass
                    continue
            except Exception:
                pass
        try:
            shutil.copy2(src, dest)
        except OSError:
            continue
        try:
            new_art = artifact_for(str(dest), kind=getattr(art, "kind", "extracted"),
                                   source=getattr(art, "source", "triage"),
                                   depth=getattr(art, "depth", 0) or 0)
        except Exception:
            continue
        new_art.source_artifact = getattr(art, "source_artifact", "") or str(path)
        persisted.append(new_art)
    # Ensure at least the original input is preserved (covers pipeline temp-staging cleanup).
    if not persisted:
        try:
            src = Path(str(path))
            if src.is_file():
                dup = _find_same(_sha(src))
                if dup is not None:
                    try:
                        new_art = artifact_for(str(dup), kind="file", source="triage", depth=0)
                        new_art.source_artifact = str(path)
                        persisted.append(new_art)
                    except Exception:
                        pass
                else:
                    index += 1
                    safe_base = re.sub(r"[^A-Za-z0-9._-]", "_", src.name) or "file"
                    dest = ws / f"artifact-{index:03d}-{safe_base}"
                    while dest.exists():
                        try:
                            if _sha(dest) == _sha(src):
                                break
                        except Exception:
                            pass
                        index += 1
                        dest = ws / f"artifact-{index:03d}-{safe_base}"
                    try:
                        if not (dest.exists() and _sha(dest) == _sha(src)):
                            shutil.copy2(src, dest)
                        new_art = artifact_for(str(dest), kind="file", source="triage", depth=0)
                        new_art.source_artifact = str(path)
                        persisted.append(new_art)
                    except OSError:
                        pass
        except Exception:
            pass
    else:
        # If pipeline cleaned temp staging, re-extract archive content flat into workspace.
        try:
            from ..shared import archives as _A
            from ..shared.files import magic as _magic
            head = b""
            try:
                head = Path(str(path)).read_bytes()[:32]
            except OSError:
                head = b""
            low = str(path).lower()
            looks_archive = _magic(head).lower().find("archive") >= 0 or low.endswith(
                (".zip", ".tar", ".tgz", ".tar.gz", ".gz", ".bz2", ".xz", ".7z", ".rar"))
            has_extracted = any(getattr(a, "kind", "") == "extracted" for a in persisted)
            if looks_archive and not has_extracted:
                try:
                    from ..analysis.budget import AnalysisBudget as _B
                    _b = _B.named("balanced")
                except Exception:
                    _b = None
                ok, _msg, _arts = _A.extract_with_artifacts(str(path), str(ws), budget=_b, parent=str(path))
                for a in (_arts or []):
                    # extract_with_artifacts already wrote flat artifact-XXX files into ws;
                    # relocate bookkeeping to persisted list without re-copying.
                    try:
                        p = Path(a.path)
                        if p.is_file() and ws.resolve() == p.resolve().parent:
                            persisted.append(a)
                    except Exception:
                        continue
        except Exception:
            pass
    # Save solve-report.json with parent links.
    report_path = None
    try:
        flags = [f for fd in (findings or []) for f in (getattr(fd, "flags", []) or [])]
        status = "incomplete"
        try:
            if any(getattr(fd, "status", "") == "solved" for fd in (findings or [])):
                status = "solved"
        except Exception:
            pass
        report = SolveReport(target=str(path), category="forensics", description="triage",
                             findings=list(findings or []), artifacts=list(persisted),
                             flags=flags[:20], status=status, stop_reason="triage complete")
        report_path = report.save(ws / "solve-report.json")
    except Exception:
        report_path = None
    return persisted, report_path


def _triage(path, workspace=None, budget='balanced'):
    try:
        b = AnalysisBudget.named(budget or 'balanced')
    except ValueError:
        b = AnalysisBudget.named('balanced')
    _findings, _arts, render = triage_file(path, budget=b, description="")
    # Persist artifacts flat into workspace dir (backward-compat: flag optional).
    if workspace:
        try:
            persisted, report_path = _persist_to_workspace(path, _findings, _arts, workspace)
            render += f"\nWorkspace: {workspace} (artifacts={len(persisted)}" + (f", report={report_path}" if report_path else "") + ")"
        except Exception as e:
            render += f"\nWorkspace: {workspace} (persist failed: {e})"
    print(render)

def _strings(path):
    if not which('strings'): raise SystemExit('strings is not installed.')
    print(run_tool(['strings','-a','-n','4',path],timeout=30,max_output=120000)[1])

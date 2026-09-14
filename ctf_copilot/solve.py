from __future__ import annotations
from pathlib import Path
from .crypto.analyzer import analyze as crypto_analyze
from .forensics.triage import triage as forensic_triage
from .forensics.archive import inspect as archive_inspect
from .reverse.triage import triage as reverse_triage
from .pwn.triage import triage as pwn_triage
from .web.analyzer import analyze as web_analyze, render as web_render
from .shared.files import file_report
from .shared.flags import find_flags
from .flags.scanner import scan as flag_scan
from .engine import collect_flags, Finding, Artifact
import re


def classify_file(p: Path) -> str:
    head=p.read_bytes()[:32]; suffix=p.suffix.lower()
    if head.startswith((b'\x7fELF',b'MZ')): return 'reverse/pwn'
    if suffix in {'.pcap','.pcapng'}: return 'forensics/pcap'
    if suffix in {'.zip','.7z','.rar','.tar','.gz'} or head.startswith(b'PK\x03\x04'): return 'forensics/archive'
    if suffix in {'.png','.jpg','.jpeg','.gif','.bmp','.webp','.pdf','.wav'} or head.startswith((b'\x89PNG\r\n\x1a\n',b'\xff\xd8\xff')): return 'forensics'
    if suffix in {'.py','.js','.txt','.md','.json','.xml','.html','.csv'}: return 'text/crypto'
    return 'generic-file'

def _finish(report, detail: str, flag_pattern: str | None, workspace: str | None) -> str:
    """Feed actual safe action output back into the report before rendering it."""
    flags=collect_flags(detail,flag_pattern)
    report.flags=list(dict.fromkeys(report.flags+flags))
    report.status='flag-found' if report.flags else 'needs-next-step'
    report.findings.append(Finding(report.category,'offline playbook','Completed bounded first-pass actions',.8,'Results below were produced without active probing.',flags=report.flags))
    if workspace:
        from .workspace.manager import save_report
        save_report(workspace,report)
    from .engine import render_report
    return render_report(report)+'\n\n'+detail

def _password_candidates(description: str) -> list[str]:
    """Only accept explicit clue values; never run a wordlist/brute-force attack."""
    values=re.findall(r'(?i)(?:password|passphrase|key)\s*(?:is|=|:)\s*["\']?([A-Za-z0-9_@!#$%^&*.-]{3,80})',description)
    return list(dict.fromkeys(values))[:10]


def solve(target: str, description: str = '', flag_pattern: str | None = None, workspace: str | None = None) -> str:
    from .engine import initial_report, render_report
    report = initial_report(target, description, flag_pattern)
    if report.status == 'flag-found':
        if workspace:
            from .workspace.manager import save_report
            save_report(workspace, report)
        return render_report(report)
    p=Path(target)
    if p.is_dir():
        rows=flag_scan(str(p)); lines=['CTF SOLVE - DIRECTORY','=====================',f'Path: {p}',f'Flag-like hits: {len(rows)}']
        lines += [f'  {path}: {flag}' for path,flag in rows[:50]]
        lines += ['','NEXT BEST ACTIONS','  - Inspect suspicious files individually with `ctf solve <file>`.','  - For extracted challenge trees, run `ctf flags scan <directory>`.']
        return _finish(report,'\n'.join(lines),flag_pattern,workspace)
    if p.is_file():
        from .forensics.evidence import inspect as forensic_evidence
        cat=classify_file(p); out=['CTF SOLVE - FIRST PASS','======================',f'Input: {p}',f'Suggested category: {cat}','',file_report(p),'',forensic_evidence(str(p))]
        if cat=='forensics/archive':
            passwords=_password_candidates(description)
            out += ['',archive_inspect(str(p),passwords),'','NEXT BEST ACTIONS','  - `ctf forensics recurse <archive>` for nested ZIP/text clues','  - `ctf forensics triage <archive>` for strings/binwalk clues']
        elif cat.startswith('forensics'):
            out += ['',forensic_triage(str(p))]
            if cat=='forensics/pcap': out += ['','NEXT: `ctf forensics pcap <file>`']
        elif cat=='reverse/pwn':
            out += ['',reverse_triage(str(p)),'',pwn_triage(str(p))]
        elif cat=='text/crypto':
            if p.suffix.lower()=='.py':
                from .crypto.inspect import inspect_python
                out += ['',inspect_python(str(p))]
            try:
                text=p.read_text(errors='ignore')[:200000]; results=crypto_analyze(text)
                if results:
                    out += ['','Crypto candidates:']
                    for r in results[:5]:
                        chain=' -> '.join(f'{x.kind}({x.parameter})' if x.parameter else x.kind for x in r.chain)
                        out.append(f'  {chain}: {r.output[:300]}')
            except OSError: pass
        return _finish(report,'\n'.join(out),flag_pattern,workspace)
    if target.startswith(('http://','https://')):
        from .web.playbook import map_target
        return _finish(report,web_render(web_analyze(target))+'\n\n'+map_target(target),flag_pattern,workspace)
    results=crypto_analyze(target); out=['CTF SOLVE - TEXT FIRST PASS','===========================']
    from .crypto.inspect import inspect_text
    out += ['',inspect_text(description+'\n'+target)]
    if not results:
        out.append('No strong supported encoding/cipher candidate detected.')
        out += ['','NEXT: inspect challenge context or try `ctf crypto decode --kind <known-type>`.']
    else:
        for i,r in enumerate(results[:5],1):
            chain=' -> '.join(f'{x.kind}({x.parameter})' if x.parameter else x.kind for x in r.chain); out.append(f'{i}. {chain}: {r.output}')
        found=[]
        for r in results: found.extend(find_flags(r.output))
        if found: out += ['','Possible flags:']+[f'  {x}' for x in dict.fromkeys(found)]
    return _finish(report,'\n'.join(out),flag_pattern,workspace)

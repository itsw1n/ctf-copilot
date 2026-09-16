"""PCAP summary with correlated specialist sections (bounded, tshark-only)."""
from __future__ import annotations

import re
from pathlib import Path

from ..analysis.budget import AnalysisBudget
from ..shared.flags import find_flags
from ..shared.tooling import run_tool, which
from ..crypto.analyzer import analyze


def _budget_or_default(budget):
    if budget is not None:
        return budget
    try:
        return AnalysisBudget.named("balanced")
    except Exception:
        return None


def _timeout(b) -> int:
    try:
        rem = float(b.remaining) if b is not None else 45.0
    except Exception:
        rem = 45.0
    return max(1, min(45, int(rem) if rem > 0 else 45))


def summarize(path: str, budget=None) -> str:
    p = Path(path)
    if not p.is_file():
        return f'Not a file: {p}'
    if not which('tshark'):
        return ('tshark is not installed. Open the capture in Wireshark. '
                'Decisive next: install tshark, then `ctf forensics pcap <file>` for '
                'hierarchy/endpoints/conversations/DNS/HTTP/credentials summary.')
    b = _budget_or_default(budget)
    out = ['PCAP SUMMARY', '============']

    def _run(title: str, args: list[str], cap: int = 50000) -> str:
        t = max(1, min(45, _timeout(b)))
        _rc, text = run_tool(args, timeout=t, max_output=cap)
        text = (text or '(none)').strip() or '(none)'
        out += ['', f'[{title}]', text[:8000]]
        return text

    hier = _run('protocol hierarchy', ['tshark', '-r', str(p), '-q', '-z', 'io,phs'])
    _run('endpoints', ['tshark', '-r', str(p), '-q', '-z', 'endpoints,ip'])
    _run('conversations', ['tshark', '-r', str(p), '-q', '-z', 'conv,ip'])
    dns = _run('DNS queries', ['tshark', '-r', str(p), '-Y', 'dns.qry.name', '-T', 'fields', '-e', 'dns.qry.name'])
    http = _run('HTTP requests', ['tshark', '-r', str(p), '-Y', 'http.request', '-T', 'fields',
                                  '-e', 'http.request.method', '-e', 'http.host', '-e', 'http.request.uri'])
    _run('HTTP cookies/auth', ['tshark', '-r', str(p), '-Y', 'http.cookie or http.authorization',
                               '-T', 'fields', '-e', 'http.host', '-e', 'http.cookie', '-e', 'http.authorization'], 40000)
    _run('FTP commands/creds', ['tshark', '-r', str(p), '-Y', 'ftp.request.command or ftp.request.arg',
                                '-T', 'fields', '-e', 'ftp.request.command', '-e', 'ftp.request.arg'], 30000)
    _run('UDP/ICMP overview', ['tshark', '-r', str(p), '-Y', 'udp or icmp', '-T', 'fields',
                               '-e', 'frame.number', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'dns.qry.name'], 40000)
    objs = _run('object clues (HTTP stats)', ['tshark', '-r', str(p), '-q', '-z', 'http,stat'])
    _run('object clues (SMB stats)', ['tshark', '-r', str(p), '-q', '-z', 'smb,stat'])
    _ = objs
    out += ['',
            '[object extraction handoff]',
            f'  tshark -r {p} --export-objects http,./objects-http  (bounded; review exported files for flags)',
            f'  tshark -r {p} --export-objects smb,./objects-smb   (only if hierarchy shows SMB)',
            f'  tshark -r {p} --export-objects ftp,./objects-ftp   (only if hierarchy shows FTP)',
            '  Prefer Wireshark File → Export Objects for interactive review; never exfiltrate beyond flag markers.']
    # Suspicious DNS: long labels / high entropy / many unique queries.
    try:
        names = [x.strip() for x in dns.splitlines() if x.strip()]
        uniq = sorted(set(names))
        long_names = [n for n in uniq if len(n) > 40][:10]
        if long_names:
            out += ['', '[suspicious-DNS]', 'long DNS labels (possible tunneling/exfil):'] + [f'  {n[:160]}' for n in long_names]
        elif len(uniq) > 50:
            out += ['', '[suspicious-DNS]', f'many unique DNS queries ({len(uniq)}); review for tunneling.']
    except Exception:
        pass
    # Capped TCP streams: payload text only, bounded lines.
    _rc, payload = run_tool(['tshark', '-r', str(p), '-Y', 'tcp', '-T', 'fields', '-e', 'data.text'],
                            timeout=max(1, min(45, _timeout(b))), max_output=120000)
    text = '\n'.join(x for x in (payload or '').splitlines() if x)
    # credential hints in payload text
    creds = []
    for line in text.splitlines()[:500]:
        if re.search(r"(?i)(user(name)?|pass(word)?|login|auth|token|session|cookie)\s*[:=]", line):
            creds.append(line.strip()[:200])
            if len(creds) >= 10:
                break
    if creds:
        out += ['', '[credential hints]'] + [f'  {c}' for c in creds]
    flags = find_flags(text)
    if flags:
        out += ['', '[possible flags in TCP payloads]'] + [f'  {x}' for x in flags]
    decoded = []
    for row in text.splitlines()[:300]:
        if 8 <= len(row) <= 10000:
            for result in analyze(row, max_depth=3, branch_limit=4, beam_width=4)[:1]:
                if find_flags(result.output):
                    decoded.append(result.output)
    if decoded:
        out += ['', '[decoded payload clues]'] + [f'  {x[:300]}' for x in dict.fromkeys(decoded)]
    # Correlation footer.
    low = (hier + "\n" + http + "\n" + dns).lower()
    corr = []
    if 'http' in low:
        corr.append("HTTP present -> check cookies/auth + Export Objects")
    if 'dns' in low:
        corr.append("DNS present -> review suspicious-DNS + endpoints")
    if 'ftp' in low:
        corr.append("FTP present -> review creds section")
    if corr:
        out += ['', '[correlation]', " | ".join(corr)]
    out += ['', 'For file transfer reconstruction, use Wireshark File → Export Objects when the protocol hierarchy shows HTTP/SMB/FTP.']
    return '\n'.join(out)

"""Image/audio stego triage with correlated specialist results (bounded)."""
from __future__ import annotations

from pathlib import Path

from ..analysis.budget import AnalysisBudget
from ..shared.flags import find_flags_bytes
from ..shared.tooling import run_tool, which


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


def inspect(path: str, all_tools: bool = False, extract_to: str | None = None, budget=None) -> str:
    p = Path(path)
    if not p.is_file():
        return f'Not a file: {p}'
    b = _budget_or_default(budget)
    data = p.read_bytes()[:8000000]
    out = ['STEGO TRIAGE', '============']
    flags = find_flags_bytes(data)
    if flags:
        out += ['', '[possible flags]'] + [f'  {flag}' for flag in flags]
    suffix = p.suffix.lower()
    results: dict[str, str] = {}

    def _run(key: str, title: str, argv: list[str]):
        t = max(1, min(45, _timeout(b)))
        _rc, txt = run_tool(argv, timeout=t, max_output=50000)
        txt = (txt or '(no output)').strip() or '(no output)'
        results[key] = txt
        out += ['', f'[{title}]', txt[:8000]]

    if which('exiftool'):
        _run('exiftool', 'exiftool', ['exiftool', str(p)])
    if suffix == '.png' and which('pngcheck'):
        _run('pngcheck', 'pngcheck', ['pngcheck', '-v', str(p)])
    if suffix in {'.png', '.bmp'} and (all_tools or True) and which('zsteg'):
        _run('zsteg', 'zsteg', ['zsteg', str(p)])
    if suffix in {'.png', '.jpg', '.jpeg', '.gif', '.bmp'} and which('zbarimg'):
        _run('zbarimg', 'QR/barcode', ['zbarimg', '--quiet', str(p)])
    if suffix in {'.jpg', '.jpeg', '.bmp', '.wav', '.au'} and which('steghide'):
        _run('steghide', 'steghide info', ['steghide', 'info', str(p)])
    if which('binwalk'):
        _run('binwalk', 'binwalk', ['binwalk', str(p)])
    if suffix in {'.txt', '.html', '.xml', '.js', '.py'}:
        text = data.decode('utf-8', 'ignore')
        zero = sum(text.count(x) for x in ('\u200b', '\u200c', '\u200d', '\ufeff'))
        trailing = sum(1 for line in text.splitlines() if line.endswith((' ', '\t')))
        if zero or trailing:
            out += ['', f'[text stego] zero-width={zero} trailing-whitespace-lines={trailing}']
            results['text-stego'] = f"zero-width={zero} trailing={trailing}"
    # Correlation: combine specialist clues into one hypothesis.
    fired = [k for k, v in results.items() if v and v not in ('(no output)', '(none)', '')]
    interesting = []
    low_all = " ".join(results.values()).lower()
    if 'comment' in low_all or 'software' in low_all or 'gps' in low_all:
        interesting.append("metadata comment/software/GPS")
    if 'zsteg' in results and any(k in results['zsteg'].lower() for k in ('hidden', 'payload', 'data', 'channel')):
        interesting.append("zsteg LSB signal")
    if 'binwalk' in results and any(k in results['binwalk'].lower() for k in ('zip', 'rar', 'pdf', 'png', 'gzip', 'filesystem')):
        interesting.append("binwalk embedded file")
    if 'qr/barcode' in results and results['qr/barcode'] not in ('(no output)', '(none)'):
        interesting.append("QR/barcode payload")
    if 'steghide' in results and 'embedded' in results['steghide'].lower():
        interesting.append("steghide embedded data")
    if interesting:
        out += ['', '[correlation]', 'Combined hypothesis: ' + " + ".join(interesting) +
                '. Next: carve/recurse the indicated layer; verify flags in context.']
    # Recurse output correlation (bounded, offline stdlib path only).
    try:
        from .recurse import inspect as recurse_inspect
        if (suffix in {'.png', '.jpg', '.jpeg', '.gif', '.bmp'} and
                'binwalk' in results and 'zip' in results['binwalk'].lower()):
            r = recurse_inspect(str(p))[:2000]
            out += ['', '[recurse]', r]
    except Exception:
        pass
    if extract_to and which('binwalk'):
        t = max(1, min(45, _timeout(b)))
        _rc, t2 = run_tool(['binwalk', '-e', '-C', extract_to, str(p)], timeout=t, max_output=60000)
        out += ['', '[extract]', (t2 or '(no output)')[:8000]]
    if len(out) == 2:
        out.append('No matching stego helper installed for this file type.')
    out += ['', 'Next: `ctf forensics evidence <file>` for signatures and embedded data.']
    return '\n'.join(out)

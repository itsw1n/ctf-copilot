from __future__ import annotations
from pathlib import Path
from ..shared.archives import (
    list_entries, detect_crypto, test_password, extract,
    collect_password_candidates, crack_handoff, recurse_extract,
)
from ..shared.flags import find_flags_bytes


def inspect(path: str, passwords: list[str] | None = None, crack: bool = False,
            extract_to: str | None = None, budget=None, description: str = "") -> str:
    p = Path(path)
    if not p.is_file():
        return f'Not a file: {p}'
    lines = ['ARCHIVE INSPECTION', '==================']
    entries = list_entries(str(p), budget)
    if not entries:
        return '\n'.join(lines + ['Could not list archive entries (install 7z or check file).'])
    crypto = detect_crypto(str(p), budget)
    nested = [e for e in entries if str(e.get('name', '')).lower().endswith(
        ('.zip', '.tar', '.tgz', '.tar.gz', '.gz', '.bz2', '.xz', '.7z', '.rar'))]
    lines += [f'Entries: {len(entries)}', f'Encryption: {crypto}',
              f'Nested archives: {len(nested)}', '']
    for x in entries[:200]:
        lines.append(f"{x.get('name')}  size={x.get('size')} encrypted={x.get('encrypted')} method={x.get('method')}")
    if nested:
        lines += ['', 'Nested archive entries:'] + [f"  {e.get('name')}" for e in nested[:20]]
    password = None
    if crypto != 'none':
        candidates = collect_password_candidates(passwords, description, str(p))
        lines += ['', 'Password attempts (explicit + clue + filename + small defaults only; no brute-force):']
        for candidate in candidates[:20]:
            if test_password(str(p), candidate, budget):
                password = candidate
                lines.append(f'  SUCCESS: {candidate!r}')
                break
            lines.append(f'  no: {candidate!r}')
        if not password:
            lines.append('  No candidate worked. Supply --password from challenge clues.')
    if crack and not password:
        lines.append('')
        lines.append(crack_handoff(str(p), crypto))
    if extract_to:
        # refuse encrypted extraction without a working password
        if crypto != 'none' and not password:
            lines += ['', 'Extract: skipped (encrypted; supply --password).']
        else:
            ok, msg = extract(str(p), extract_to, password, budget, description)
            lines += ['', f'Extract: {"ok" if ok else "failed"}: {msg[:500]}']
            if ok:
                # light nested-flag note (bounded, offline)
                try:
                    flags: list[str] = []
                    for f in sorted(Path(extract_to).rglob('*'))[:200]:
                        if f.is_file() and not f.is_symlink():
                            try:
                                blob = f.read_bytes()[:2_000_000]
                            except OSError:
                                continue
                            for fl in find_flags_bytes(blob):
                                if fl not in flags:
                                    flags.append(fl)
                    if flags:
                        lines += ['', 'Flags in extracted content:'] + [f'  {x}' for x in flags[:20]]
                except Exception:
                    pass
    lines += ['', 'Next: `ctf forensics recurse <archive>` for nested layers.']
    return '\n'.join(lines)

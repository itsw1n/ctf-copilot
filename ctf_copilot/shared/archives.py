"""Small, bounded archive wrapper shared by forensic commands.

Safe extraction boundaries (Task 9):
- stdlib ZIP/tar/gzip/bzip2/xz + guarded 7z for 7z/RAR
- reject absolute / drive / traversal paths, unsafe links
- enforce entry-count and advertised/actual size limits via AnalysisBudget
- staging dir + flat workspace copy with collision-safe names
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from .tooling import run_tool, which

DEFAULT_PASSWORDS = [
    "password", "123456", "ctf", "flag", "challenge",
    "picoctf", "htb", "thm", "qwerty", "letmein",
    "admin", "infected",
]

ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".gz", ".bz2", ".xz", ".7z", ".rar")
NESTED_SUFFIXES = (".zip", ".tar", ".tgz", ".tar.gz", ".gz", ".bz2", ".xz", ".7z", ".rar")


def _budget_or_default(budget=None):
    if budget is not None:
        return budget
    from ..analysis.budget import AnalysisBudget
    return AnalysisBudget.named("balanced")


def _seven() -> str | None:
    return which('7z') or which('7zz')


def _is_unsafe_name(name: str) -> str | None:
    if not name:
        return "empty name"
    norm = name.replace("\\", "/")
    if norm.startswith("/") or norm.startswith("\\"):
        return "absolute path"
    if re.match(r"^[A-Za-z]:", norm):
        return "drive path"
    parts = PurePosixPath(norm).parts
    if ".." in parts:
        return "path traversal"
    if norm.startswith("~"):
        return "home-relative path"
    return None


def _is_symlink_zip(info: zipfile.ZipInfo) -> bool:
    # Unix file type in external_attr upper 16 bits; symlink = 0o120000
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def _stdlib_zip_entries(path: str) -> list[dict] | None:
    try:
        if not zipfile.is_zipfile(path):
            return None
    except Exception:
        return None
    try:
        with zipfile.ZipFile(path) as z:
            rows = []
            for info in z.infolist():
                rows.append({
                    "name": info.filename,
                    "size": info.file_size,
                    "comp_size": info.compress_size,
                    "encrypted": bool(info.flag_bits & 0x1),
                    "method": "AES" if info.flag_bits & 0x1 and info.compress_type == 99 else ("deflate" if info.compress_type == 8 else "store"),
                    "is_dir": info.is_dir(),
                    "is_symlink": _is_symlink_zip(info),
                    "nested": info.filename.lower().endswith(NESTED_SUFFIXES),
                })
            return rows
    except Exception:
        return None


def _stdlib_tar_entries(path: str) -> list[dict] | None:
    try:
        with tarfile.open(path, "r:*") as t:
            rows = []
            for m in t.getmembers():
                rows.append({
                    "name": m.name,
                    "size": m.size,
                    "encrypted": False,
                    "method": "tar",
                    "is_dir": m.isdir(),
                    "is_symlink": m.issym() or m.islnk(),
                    "linkname": m.linkname if (m.issym() or m.islnk()) else "",
                    "nested": m.name.lower().endswith(NESTED_SUFFIXES),
                })
            return rows
    except Exception:
        return None


def _single_entries(path: str) -> list[dict] | None:
    low = path.lower()
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError:
        return None
    if low.endswith(".gz") and not low.endswith(".tar.gz") and not low.endswith(".tgz"):
        return [{"name": p.stem, "size": size * 3, "comp_size": size, "encrypted": False,
                 "method": "gzip", "is_dir": False, "is_symlink": False, "nested": False,
                 "single": True, "format": "gzip"}]
    if low.endswith(".bz2"):
        return [{"name": p.stem, "size": size * 3, "comp_size": size, "encrypted": False,
                 "method": "bzip2", "is_dir": False, "is_symlink": False, "nested": False,
                 "single": True, "format": "bzip2"}]
    if low.endswith(".xz"):
        return [{"name": p.stem, "size": size * 3, "comp_size": size, "encrypted": False,
                 "method": "xz", "is_dir": False, "is_symlink": False, "nested": False,
                 "single": True, "format": "xz"}]
    return None


def _seven_entries(path: str, budget=None) -> list[dict]:
    tool = _seven()
    if not tool:
        return []
    b = _budget_or_default(budget)
    timeout = max(1, min(45, int(b.remaining) if b.remaining > 0 else 45))
    _, text = run_tool([tool, 'l', '-slt', path], timeout=timeout, max_output=120000)
    rows = []
    current: dict = {}
    for line in text.splitlines():
        if ' = ' not in line:
            continue
        key, value = line.split(' = ', 1)
        if key == 'Path' and current:
            if current.get('Path') != path:
                rows.append({'name': current.get('Path', ''), 'size': current.get('Size', '?'),
                             'encrypted': bool(current.get('Encrypted')), 'method': current.get('Method', '?')})
            current = {}
        current[key] = value
    if current and current.get('Path') != path:
        rows.append({'name': current.get('Path', ''), 'size': current.get('Size', '?'),
                     'encrypted': bool(current.get('Encrypted')), 'method': current.get('Method', '?')})
    return rows


def list_entries(path: str, budget=None) -> list[dict]:
    """List entries via stdlib first (offline), 7z fallback for 7z/RAR."""
    rows = _stdlib_zip_entries(path)
    if rows is not None:
        return rows
    rows = _stdlib_tar_entries(path)
    if rows is not None:
        return rows
    rows = _single_entries(path)
    if rows is not None:
        return rows
    return _seven_entries(path, budget)


def detect_crypto(path: str, budget=None) -> str:
    entries = list_entries(path, budget)
    if not entries:
        # unknown format: keep legacy contract
        tool = _seven()
        if tool:
            _, text = run_tool([tool, 'l', '-slt', path], timeout=10, max_output=20000)
            if 'Encrypted = +' in text:
                return 'zipcrypto'
        return 'unknown'
    methods = ' '.join(str(x.get('method', '')) for x in entries).lower()
    if 'aes' in methods:
        return 'aes'
    if any(x.get('encrypted') for x in entries):
        return 'zipcrypto'
    return 'none'


def test_password(path: str, password: str, budget=None) -> bool:
    # Prefer stdlib probe for ZIP; fall back to 7z test.
    try:
        with zipfile.ZipFile(path) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if not infos:
                return False
            target = next((i for i in infos if i.flag_bits & 0x1), infos[0])
            try:
                z.read(target, pwd=password.encode())
                return True
            except RuntimeError:
                return False
            except zipfile.BadZipFile:
                return False
            except Exception:
                pass
    except Exception:
        pass
    tool = _seven()
    if not tool:
        return False
    b = _budget_or_default(budget)
    timeout = max(1, min(45, int(b.remaining) if b.remaining > 0 else 45))
    rc, _ = run_tool([tool, 't', f'-p{password}', path], timeout=timeout, max_output=40000)
    return rc == 0


def collect_password_candidates(explicit: list[str] | None = None,
                                description: str = "",
                                archive_path: str = "") -> list[str]:
    """Passwords ONLY from explicit args + description clues + filename tokens + small defaults."""
    seen: list[str] = []
    def add(v: str):
        v = (v or "").strip()
        if v and v not in seen:
            seen.append(v)
    for v in (explicit or []):
        add(v)
    if description:
        for m in re.findall(r"(?i)(?:password|passphrase|pass|key)\s*(?:is|=|:)\s*([^\s,;'\"]{1,64})", description):
            add(m)
    if archive_path:
        stem = Path(archive_path).stem
        for tok in re.split(r"[^A-Za-z0-9]+", stem):
            if 2 <= len(tok) <= 32:
                add(tok)
    for v in DEFAULT_PASSWORDS:
        add(v)
        if len(seen) >= (len(explicit or []) + 12 + 4):
            break
    # cap: explicit + ~12 defaults + few description/filename tokens
    return seen[:32]


def crack_handoff(path: str, crypto: str) -> str:
    return (
        f"Cracking is not automated. Handoff for {Path(path).name} (crypto={crypto}):\n"
        f"  ZIP/7z hash: 7z2john.pl {path} > hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\n"
        f"  ZIP direct: fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u {path}\n"
        f"  RAR hash: rar2john {path} > hash.txt && hashcat -m 13000 hash.txt /usr/share/wordlists/rockyou.txt"
    )


def _validate_entries(entries: list[dict], budget) -> tuple[bool, str]:
    files = [e for e in entries if not e.get("is_dir")]
    if len(files) > budget.max_archive_entries:
        return False, f"rejected: entry count {len(files)} exceeds limit {budget.max_archive_entries}"
    total_advertised = 0
    for e in entries:
        if e.get("is_dir"):
            continue
        name = str(e.get("name", ""))
        reason = _is_unsafe_name(name)
        if reason:
            return False, f"rejected: unsafe entry {name!r} ({reason})"
        if e.get("is_symlink"):
            target = str(e.get("linkname", "") or "<symlink>")
            # symlinks rejected unless explicitly safe relative link staying inside;
            # conservative: reject all symlinks/hardlinks in archives
            return False, f"rejected: unsafe symlink/hardlink {name!r} -> {target!r}"
        try:
            size = int(str(e.get("size", 0)).split()[0])
        except (ValueError, TypeError):
            size = 0
        if size < 0:
            return False, f"rejected: negative size for {name!r}"
        if size > budget.max_file_bytes:
            return False, f"rejected: entry {name!r} advertised size {size} exceeds single-file limit {budget.max_file_bytes}"
        total_advertised += size
        if total_advertised > budget.max_total_bytes:
            return False, f"rejected: total advertised size exceeds limit {budget.max_total_bytes}"
    if any(e.get("encrypted") for e in entries):
        return True, "encrypted"
    return True, "ok"


def _safe_join(staging: Path, name: str) -> Path | None:
    target = staging / name
    try:
        resolved = target.resolve()
        staging_res = staging.resolve()
        if resolved != staging_res and staging_res not in resolved.parents:
            return None
        return target
    except Exception:
        return None


def extract(path: str, outdir: str, password: str | None = None, budget=None,
            description: str = "") -> tuple[bool, str]:
    """Backward-compat safe extraction. Returns (ok, message)."""
    ok, msg, _arts = extract_with_artifacts(path, outdir, password=password, budget=budget,
                                            description=description, depth=0)
    return ok, msg


def extract_with_artifacts(path: str, outdir: str, password: str | None = None, budget=None,
                           description: str = "", depth: int = 0,
                           parent: str = "") -> tuple[bool, str, list]:
    """Safe extract into flat workspace; returns (ok, message, artifacts)."""
    from ..analysis.runner import artifact_for  # local import to avoid cycle
    b = _budget_or_default(budget)
    p = Path(path)
    if not p.is_file():
        return False, f"Not a file: {p}", []
    entries = list_entries(str(p), b)
    if not entries:
        # fall back to 7z-guarded path for opaque formats; if no tool, report unknown
        tool = _seven()
        if not tool:
            return False, "Could not list archive entries (unsupported format or install 7z).", []
        return _seven_extract(str(p), outdir, password, b, depth, parent)
    valid, reason = _validate_entries(entries, b)
    if not valid:
        return False, reason, []
    encrypted = any(e.get("encrypted") for e in entries)
    if encrypted and not password:
        return False, "rejected: archive is encrypted; supply --password (no brute-force attempted)", []
    if encrypted and password and not test_password(str(p), password, b):
        return False, "rejected: supplied password did not unlock archive", []
    # single-file compressed (gzip/bzip2/xz)
    single = next((e for e in entries if e.get("single")), None)
    if single:
        return _extract_single(str(p), single, outdir, b, depth, parent)
    # ZIP stdlib path
    if _stdlib_zip_entries(str(p)) is not None:
        return _extract_zip(str(p), entries, outdir, password, b, depth, parent)
    # tar stdlib path
    if _stdlib_tar_entries(str(p)) is not None:
        return _extract_tar(str(p), entries, outdir, password, b, depth, parent)
    # opaque: 7z
    return _seven_extract(str(p), outdir, password, b, depth, parent)


def _copy_to_workspace(staging: Path, outdir: Path, depth: int, parent: str) -> tuple[list, str]:
    from ..analysis.runner import artifact_for
    outdir.mkdir(parents=True, exist_ok=True)
    arts: list = []
    total = 0
    index = 0
    for src in sorted(staging.rglob("*")):
        if src.is_dir() or src.is_symlink():
            if src.is_symlink():
                continue
            continue
        size = src.stat().st_size
        total += size
        index += 1
        safe_base = re.sub(r"[^A-Za-z0-9._-]", "_", src.name) or "file"
        dest = outdir / f"artifact-{index:03d}-{safe_base}"
        shutil.copy2(src, dest)
        art = artifact_for(str(dest), kind="extracted", source=parent or "archive", depth=depth)
        art.source_artifact = parent
        arts.append(art)
    return arts, f"extracted {len(arts)} file(s) ({total} bytes)"


def _check_staging(staging: Path, b) -> tuple[bool, str, int]:
    total = 0
    staging_res = staging.resolve()
    for root, dirs, files in os.walk(staging, followlinks=False):
        for name in dirs + files:
            full = Path(root) / name
            try:
                resolved = full.resolve()
            except Exception:
                return False, f"rejected: cannot resolve {full}", 0
            if resolved != staging_res and staging_res not in resolved.parents:
                return False, f"rejected: entry escapes staging: {name!r}", 0
            if full.is_symlink():
                try:
                    target = Path(os.readlink(full))
                    (staging / target if not target.is_absolute() else target)
                    r = (staging / target).resolve() if not target.is_absolute() else target.resolve()
                    if r != staging_res and staging_res not in r.parents:
                        return False, f"rejected: unsafe symlink target {name!r}", 0
                except Exception:
                    return False, f"rejected: unsafe symlink {name!r}", 0
                continue
            if full.is_file():
                try:
                    size = full.stat().st_size
                except OSError:
                    continue
                if size > b.max_file_bytes:
                    return False, f"rejected: extracted file {name!r} size {size} exceeds single-file limit {b.max_file_bytes}", 0
                total += size
                if total > b.max_total_bytes:
                    return False, f"rejected: total extracted size exceeds limit {b.max_total_bytes}", 0
    return True, "ok", total


def _read_capped(fobj, limit: int, chunk: int = 65536) -> tuple[bytes, bool]:
    """Stream-read up to limit+1 bytes; returns (data, over_limit)."""
    if limit < 0:
        limit = 0
    cap = limit + 1
    parts: list[bytes] = []
    total = 0
    while True:
        piece = fobj.read(min(chunk, cap - total))
        if not piece:
            break
        parts.append(piece)
        total += len(piece)
        if total > limit:
            # drain no further; signal over-limit without huge alloc
            return b"".join(parts), True
    return b"".join(parts), False


def _decompress_single_streamed(fmt: str, raw: bytes, limit: int) -> tuple[bytes | None, bool, str]:
    """Streamed single-file decompress with cap. Returns (data, over_limit, err)."""
    cap = limit + 1
    try:
        if fmt == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gf:
                data, over = _read_capped(gf, limit)
                return data, over, ""
        if fmt == "bzip2":
            dec = bz2.BZ2Decompressor()
            out = bytearray()
            step = 65536
            pos = 0
            while pos < len(raw):
                try:
                    piece = dec.decompress(raw[pos:pos + step], cap - len(out))
                except Exception as e:
                    return None, False, str(e)
                out.extend(piece)
                pos += step
                if len(out) > limit:
                    return bytes(out), True, ""
                if dec.eof:
                    break
            # flush remainder within cap
            while not dec.eof:
                try:
                    piece = dec.decompress(b"", cap - len(out))
                except Exception:
                    break
                if not piece:
                    break
                out.extend(piece)
                if len(out) > limit:
                    return bytes(out), True, ""
            return bytes(out), False, ""
        # xz / lzma
        dec = lzma.LZMADecompressor()
        out = bytearray()
        step = 65536
        pos = 0
        while pos < len(raw):
            try:
                piece = dec.decompress(raw[pos:pos + step], cap - len(out))
            except Exception as e:
                return None, False, str(e)
            if piece:
                out.extend(piece)
            pos += step
            if len(out) > limit:
                return bytes(out), True, ""
            if dec.eof:
                break
        return bytes(out), False, ""
    except Exception as e:
        return None, False, str(e)


def _extract_zip(path: str, entries: list[dict], outdir: str, password, b, depth, parent) -> tuple[bool, str, list]:
    staging = Path(tempfile.mkdtemp(prefix="ctf-staging-"))
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                if _is_unsafe_name(info.filename):
                    return False, f"rejected: unsafe entry {info.filename!r} (path traversal)", []
                if _is_symlink_zip(info):
                    return False, f"rejected: unsafe symlink/hardlink {info.filename!r}", []
                dest = _safe_join(staging, info.filename)
                if dest is None:
                    return False, f"rejected: unsafe entry {info.filename!r} (path traversal)", []
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    pwd = password.encode() if password else None
                    with z.open(info, pwd=pwd) as fobj:
                        data, over = _read_capped(fobj, b.max_file_bytes)
                except RuntimeError as e:
                    return False, f"rejected: need password ({e})", []
                if over:
                    return False, f"rejected: entry {info.filename!r} actual size exceeds single-file limit", []
                dest.write_bytes(data)
        ok, reason, _total = _check_staging(staging, b)
        if not ok:
            return False, reason, []
        arts, msg = _copy_to_workspace(staging, Path(outdir), depth + 1, parent or path)
        for a in arts:
            a.depth = depth + 1
        return True, msg, arts
    except zipfile.BadZipFile as e:
        return False, f"rejected: bad zip ({e})", []
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _extract_tar(path: str, entries: list[dict], outdir: str, password, b, depth, parent) -> tuple[bool, str, list]:
    staging = Path(tempfile.mkdtemp(prefix="ctf-staging-"))
    try:
        with tarfile.open(path, "r:*") as t:
            for m in t.getmembers():
                if m.isdir():
                    continue
                if m.issym() or m.islnk():
                    return False, f"rejected: unsafe symlink/hardlink {m.name!r}", []
                if _is_unsafe_name(m.name):
                    return False, f"rejected: unsafe entry {m.name!r} (path traversal)", []
                dest = _safe_join(staging, m.name)
                if dest is None:
                    return False, f"rejected: unsafe entry {m.name!r} (path traversal)", []
                f = t.extractfile(m)
                if f is None:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                data, over = _read_capped(f, b.max_file_bytes)
                if over:
                    return False, f"rejected: entry {m.name!r} actual size exceeds single-file limit", []
                dest.write_bytes(data)
        ok, reason, _total = _check_staging(staging, b)
        if not ok:
            return False, reason, []
        arts, msg = _copy_to_workspace(staging, Path(outdir), depth + 1, parent or path)
        for a in arts:
            a.depth = depth + 1
        return True, msg, arts
    except (tarfile.TarError, OSError) as e:
        return False, f"rejected: bad tar ({e})", []
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _extract_single(path: str, entry: dict, outdir: str, b, depth, parent) -> tuple[bool, str, list]:
    fmt = entry.get("format", "gzip")
    raw = Path(path).read_bytes()
    data, over, err = _decompress_single_streamed(fmt, raw, b.max_file_bytes)
    if data is None:
        return False, f"rejected: decompress failed ({err})", []
    if over:
        return False, f"rejected: decompressed size exceeds single-file limit {b.max_file_bytes}", []
    staging = Path(tempfile.mkdtemp(prefix="ctf-staging-"))
    try:
        name = re.sub(r"[^A-Za-z0-9._-]", "_", str(entry.get("name", "data"))) or "data"
        (staging / name).write_bytes(data)
        ok, reason, _t = _check_staging(staging, b)
        if not ok:
            return False, reason, []
        arts, msg = _copy_to_workspace(staging, Path(outdir), depth + 1, parent or path)
        for a in arts:
            a.depth = depth + 1
        return True, msg, arts
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _seven_extract(path: str, outdir: str, password, b, depth, parent) -> tuple[bool, str, list]:
    tool = _seven()
    if not tool:
        return False, "7z is not installed.", []
    staging = Path(tempfile.mkdtemp(prefix="ctf-staging-"))
    try:
        timeout = max(1, min(45, int(b.remaining) if b.remaining > 0 else 45))
        args = [tool, 'x', '-y', f'-o{staging}'] + ([f'-p{password}'] if password else []) + [path]
        rc, text = run_tool(args, timeout=timeout, max_output=80000)
        if rc != 0:
            low = (text or "").lower()
            if "wrong password" in low or "encrypted" in low or "password" in low:
                return False, "rejected: archive is encrypted; supply --password (no brute-force attempted)", []
            return False, (text or "extraction failed")[:500], []
        ok, reason, _t = _check_staging(staging, b)
        if not ok:
            return False, reason, []
        arts, msg = _copy_to_workspace(staging, Path(outdir), depth + 1, parent or path)
        for a in arts:
            a.depth = depth + 1
        return True, msg or "extracted", arts
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _looks_like_archive_bytes(head: bytes, name: str) -> bool:
    low = name.lower()
    if low.endswith(NESTED_SUFFIXES):
        return True
    sigs = (b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")
    return any(head.startswith(s) for s in sigs)


def recurse_extract(start_path: str, workspace: str, budget=None, description: str = "",
                    passwords: list[str] | None = None, depth: int = 0,
                    seen: set[str] | None = None) -> tuple[list, list[str]]:
    """Walk extracted files, re-queue nested archives up to budget.max_depth, dedup by sha256."""
    from ..analysis.runner import artifact_for
    b = _budget_or_default(budget)
    seen = seen if seen is not None else set()
    artifacts: list = []
    notes: list[str] = []
    queue: list[tuple[str, int, str]] = [(start_path, depth, start_path)]
    while queue and b.can_continue():
        cur, d, parent = queue.pop(0)
        if d > b.max_depth:
            notes.append(f"{cur}: max depth {b.max_depth} reached")
            continue
        try:
            digest = hashlib.sha256(Path(cur).read_bytes()).hexdigest()
        except OSError:
            continue
        if digest in seen:
            continue
        seen.add(digest)
        entries = list_entries(cur, b)
        if not entries:
            continue
        # encrypted nested archives: report, don't extract
        if any(e.get("encrypted") for e in entries):
            notes.append(f"{Path(cur).name}: encrypted archive (supply --password)")
            continue
        if len([e for e in entries if not e.get("is_dir")]) > b.max_archive_entries:
            notes.append(f"{Path(cur).name}: too many entries, skipped")
            continue
        tmpws = Path(workspace) / f"layer-{d}-{digest[:8]}"
        ok, msg, arts = extract_with_artifacts(cur, str(tmpws), password=None, budget=b,
                                               description=description, depth=d, parent=parent)
        if not ok:
            # try password candidates for nested layer
            cands = collect_password_candidates(passwords, description, cur)
            unlocked = False
            for cand in cands[:12]:
                if test_password(cur, cand, b):
                    ok2, msg2, arts2 = extract_with_artifacts(cur, str(tmpws), password=cand,
                                                             budget=b, description=description,
                                                             depth=d, parent=parent)
                    if ok2:
                        ok, msg, arts = ok2, f"{msg2} (password from candidates)", arts2
                        unlocked = True
                        break
            if not unlocked:
                notes.append(f"{Path(cur).name}: {msg}")
                continue
        for a in arts:
            if not b.consume_artifact(a.size):
                notes.append("artifact or byte budget exhausted")
                queue.clear()
                break
            artifacts.append(a)
            try:
                head = Path(a.path).read_bytes()[:16]
            except OSError:
                continue
            if _looks_like_archive_bytes(head, a.path) and d + 1 <= b.max_depth:
                queue.append((a.path, d + 1, a.path))
    return artifacts, notes

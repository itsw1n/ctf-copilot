"""Unified budgeted forensics triage pipeline (Task 9)."""
from __future__ import annotations

import hashlib
import math
import re
import tempfile
from pathlib import Path

from ..analysis.budget import AnalysisBudget
from ..analysis.models import Artifact, Finding
from ..analysis.runner import artifact_for
from ..shared.files import magic, printable_strings
from ..shared.flags import find_flags, find_flags_bytes, validate_flags
from ..shared.tooling import run_tool, which

EMBEDDED_SIGS = (
    (b"PK\x03\x04", "ZIP"),
    (b"%PDF-", "PDF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
)

EXT_MAGIC_EXPECTED = {
    ".png": "PNG image", ".jpg": "JPEG image", ".jpeg": "JPEG image",
    ".gif": "GIF image", ".bmp": "BMP image", ".pdf": "PDF document",
    ".zip": "ZIP archive", ".gz": "GZIP archive", ".tgz": "GZIP archive",
    ".bz2": "BZIP2 archive", ".xz": "XZ archive", ".7z": "7Z archive",
    ".rar": "RAR archive", ".mp3": "MP3 audio", ".ogg": "OGG media",
    ".wav": "RIFF/WAV media", ".pcap": "PCAP capture", ".pcapng": "PCAPNG capture",
}


def _budget_or_default(budget) -> AnalysisBudget:
    if budget is not None:
        return budget
    return AnalysisBudget.named("balanced")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def detect_type(magic_str: str, suffix: str, data: bytes = b"") -> str:
    m = (magic_str or "").lower()
    s = (suffix or "").lower()
    if "zip" in m or "gzip" in m or "bzip2" in m or "xz" in m or "7z" in m or "rar" in m:
        return "archive"
    if s in (".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar") or s == ".tar.gz":
        return "archive"
    if "png" in m or "jpeg" in m or "gif" in m or "bmp" in m or "tiff" in m:
        return "image"
    if "ogg" in m or "flac" in m or "riff" in m or "mp3" in m:
        return "audio"
    if "pdf" in m or "ole" in m or "rtf" in m:
        return "document"
    if "pcap" in m:
        return "pcap"
    if s in (".pcap", ".pcapng", ".cap"):
        return "pcap"
    if s in (".img", ".dd", ".e01", ".raw", ".bin") and len(data) > 1_000_000:
        return "disk"
    if s in (".mem", ".dump", ".lime", ".dmp"):
        return "memory"
    if data:
        sample = data[:65536]
        try:
            txt = sample.decode("utf-8")
            ratio = sum(1 for c in txt if c.isprintable() or c in "\n\r\t") / max(1, len(txt))
        except Exception:
            ratio = 0.0
        if ratio > 0.85:
            return "text"
    if s in (".txt", ".md", ".json", ".xml", ".html", ".csv", ".py", ".js", ".c"):
        return "text"
    return "binary"


def _cap(text: str, budget: AnalysisBudget) -> str:
    limit = max(1024, budget.max_output_bytes)
    if len(text) > limit:
        return text[:limit] + "\n... output truncated (budget) ..."
    return text


def triage_file(path, budget=None, description: str = "", flag_pattern: str | None = None):
    """Budgeted first-pass triage. Returns (findings, artifacts, render)."""
    b = _budget_or_default(budget)
    p = Path(str(path))
    findings: list[Finding] = []
    artifacts: list[Artifact] = []

    def _finding(category, tool, observation, confidence=0.5, why="", actions=None,
                 flags=None, status="candidate", evidence=None, technique=""):
        return Finding(category, tool, observation, confidence, why, actions or [],
                       flags or [], technique, status, evidence or [])

    if not p.is_file():
        f = _finding("forensics", "triage", f"Not a file: {p}", 1.0,
                     "input path does not exist", [], [], "inconclusive", [str(p)])
        return [f], [], f"Not a file: {p}"

    try:
        art = artifact_for(str(p), kind="file", source=description or "triage", depth=0)
    except Exception as e:
        f = _finding("forensics", "triage", f"cannot read input: {e}", 0.9, str(e),
                     [], [], "inconclusive", [str(p)])
        return [f], [], f"cannot read input: {e}"
    size = art.size
    if not b.can_continue(size=size):
        f = _finding("forensics", "budget", "budget exhausted before triage", 1.0,
                     "artifact or byte budget exhausted", [], [], "inconclusive", [str(p)])
        return [f], [], "budget exhausted before triage"
    b.consume_artifact(size)
    artifacts.append(art)

    try:
        data = p.read_bytes()[:8_000_000]
    except OSError as e:
        f = _finding("forensics", "triage", f"cannot read input: {e}", 0.9, str(e),
                     [], [], "inconclusive", [str(p)])
        return [f], [], f"cannot read input: {e}"
    head = data[:32]
    magic_str = magic(head)
    suffix = p.suffix.lower()
    sha = hashlib.sha256(data).hexdigest()
    ent = _entropy(data[:262144])

    # 1. file cmd + internal magic
    file_out = ""
    if which("file") and b.can_continue():
        _rc, file_out = run_tool(["file", str(p)], timeout=max(1, min(15, int(b.remaining) or 15)),
                                 max_output=8000)
    findings.append(_finding(
        "forensics", "file+magic",
        f"magic={magic_str}; file={file_out.strip() or 'n/a'}; size={size}; sha256={sha[:16]}...",
        0.9, "internal magic correlates filename with content type",
        ["compare extension vs magic; follow mismatch clues"],
        [], "detected", [f"magic={magic_str}", f"size={size}", f"sha256={sha}"]))
    findings.append(_finding(
        "forensics", "identity",
        f"sha256={sha} size={size} entropy={ent}", 1.0,
        "content identity and randomness baseline",
        [], [], "detected", [f"sha256={sha}", f"entropy={ent}"]))

    # 2. ext/magic mismatch
    expected = EXT_MAGIC_EXPECTED.get(suffix)
    if expected and expected != magic_str:
        findings.append(_finding(
            "forensics", "mismatch",
            f"extension {suffix} expects {expected} but magic is {magic_str} (mismatch)",
            0.85, "renamed file or polyglot container",
            ["ctf forensics evidence <file>", "check embedded signatures below"],
            [], "detected", [f"ext={suffix}", f"expected={expected}", f"magic={magic_str}"]))

    # 3. strings + flags (UTF-8/UTF-16)
    try:
        u8 = data.decode("utf-8", "ignore")
    except Exception:
        u8 = ""
    try:
        u16le = data.decode("utf-16le", "ignore")
    except Exception:
        u16le = ""
    try:
        u16be = data.decode("utf-16be", "ignore")
    except Exception:
        u16be = ""
    joined = "\n".join([u8] + printable_strings(data)[:2000] + [u16le[:20000], u16be[:20000]])
    raw_flags = find_flags(joined) + [f for f in find_flags_bytes(data) if f not in find_flags(joined)]
    raw_flags = list(dict.fromkeys(raw_flags))
    confirmed, candidates = validate_flags(joined + "\n" + "\n".join(raw_flags),
                                           pattern=flag_pattern, source_kind="extracted")
    # merge byte-level flags that validate_flags may have missed as candidates
    for f in raw_flags:
        if f not in confirmed and f not in candidates:
            candidates.append(f)
    if confirmed:
        findings.append(_finding(
            "forensics", "strings", f"confirmed flags: {', '.join(confirmed[:10])}", 0.95,
            "flag pattern matched explicitly", ["verify flag context; submit if in scope"],
            confirmed, "solved", confirmed[:10]))
    if candidates:
        findings.append(_finding(
            "forensics", "strings", f"candidate flags: {', '.join(candidates[:10])}", 0.6,
            "flag-like text without confirming context; placeholders rejected",
            ["validate surrounding context; decode/extract source if derived"],
            candidates, "candidate", candidates[:10]))
    if not confirmed and not candidates:
        findings.append(_finding(
            "forensics", "strings", "no flag-like strings in UTF-8/UTF-16 view", 0.4,
            "readable text scanned; nothing flag-shaped", ["try metadata/embedded/crypto paths"],
            [], "inconclusive", [f"strings_scanned={len(joined)}"]))

    # 4. metadata (guarded)
    if b.can_continue():
        try:
            from .metadata import show as metadata_show
            meta = metadata_show(str(p))
            findings.append(_finding(
                "forensics", "metadata", (_cap(meta, b)[:2000]),
                0.5, "EXIF/document metadata may hide clues",
                ["inspect GPS/software/comment fields"], [], "candidate", [meta[:500]]))
            meta_blob = meta
        except Exception as e:
            meta_blob = f"metadata unavailable: {e}"
            findings.append(_finding(
                "forensics", "metadata", meta_blob, 0.3,
                "metadata helper guarded", [], [], "inconclusive", [str(e)]))
    else:
        meta_blob = "metadata skipped (budget)"

    # 5. embedded signatures + appended data
    offsets = []
    for sig, name in EMBEDDED_SIGS:
        idx = data.find(sig)
        count = 0
        start = 0
        while True:
            j = data.find(sig, start)
            if j < 0:
                break
            offsets.append((j, name))
            count += 1
            start = j + 1
            if count > 10:
                break
    offsets.sort()
    primary_end = 0
    # rough primary-length heuristic: first embedded offset beyond small header
    if offsets:
        first_off, first_name = offsets[0]
        if first_off == 0:
            rest = [(o, n) for (o, n) in offsets if o > 0]
        else:
            rest = offsets
        for off, name in rest:
            findings.append(_finding(
                "forensics", "carve",
                f"embedded {name} signature at byte {off}", 0.75,
                "container holds another file; possible polyglot/appended data",
                ["ctf forensics recurse <file>", "binwalk -e for carving (bounded)"],
                [], "detected", [f"{name}@{off}"]))
        # appended-data: primary magic known and trailing ZIP/PDF/PNG far into file
        if magic_str != "Unknown / generic binary" and rest:
            biggest = rest[-1]
            findings.append(_finding(
                "forensics", "appended",
                f"appended-data suspected: {biggest[1]} at byte {biggest[0]} after {magic_str} header",
                0.8, "data beyond primary format suggests appended archive/image",
                ["carve trailing bytes; recurse into appended region"],
                [], "detected", [f"{n}@{o}" for o, n in rest]))
        _ = primary_end

    # 6. type detection
    ftype = detect_type(magic_str, suffix, data)
    findings.append(_finding(
        "forensics", "classify", f"type={ftype} (magic={magic_str}, ext={suffix or '(none)'})",
        0.8, "routes low-cost specialist dispatch", [], [], "detected", [ftype]))

    # 7. specialist dispatch (low-cost only, no heavy carving)
    if ftype == "archive" and b.can_continue():
        try:
            from ..shared import archives as A
            entries = A.list_entries(str(p), b)
            crypto = A.detect_crypto(str(p), b)
            nested = [e for e in entries if e.get("nested")]
            enc_n = sum(1 for e in entries if e.get("encrypted"))
            obs = (f"archive: {len(entries)} entries, crypto={crypto}, "
                   f"nested={len(nested)}, encrypted_entries={enc_n}")
            findings.append(_finding(
                "forensics", "archive-inspect", obs, 0.8,
                "entry/encryption/nesting survey before extraction",
                ["ctf forensics archive <file> [--password ...]", "ctf forensics recurse <file>"],
                [], "detected", [str(e.get('name')) for e in entries[:10]]))
            # bounded nested-flag scan via safe extraction (stdlib, no carving tools)
            try:
                tmpws = Path(tempfile.mkdtemp(prefix="ctf-triage-"))
                ok, msg, arts = A.extract_with_artifacts(str(p), str(tmpws), password=None,
                                                         budget=b, description=description, depth=0,
                                                         parent=str(p))
                inner_flags: list[str] = []
                if ok:
                    for a in arts:
                        artifacts.append(a)
                        try:
                            blob = Path(a.path).read_bytes()[:2_000_000]
                        except OSError:
                            continue
                        for fl in find_flags_bytes(blob):
                            if fl not in inner_flags:
                                inner_flags.append(fl)
                        # one nested level: if extracted file is itself a zip, scan members in-memory
                        try:
                            import io as _io
                            import zipfile as _zf
                            if _zf.is_zipfile(_io.BytesIO(blob)):
                                with _zf.ZipFile(_io.BytesIO(blob)) as z2:
                                    for info in z2.infolist()[:b.max_archive_entries]:
                                        if info.is_dir() or (info.flag_bits & 0x1):
                                            continue
                                        try:
                                            child = z2.read(info)[:2_000_000]
                                        except Exception:
                                            continue
                                        for fl in find_flags_bytes(child):
                                            if fl not in inner_flags:
                                                inner_flags.append(fl)
                        except Exception:
                            pass
                    if inner_flags:
                        c2, cand2 = validate_flags("\n".join(inner_flags), pattern=flag_pattern,
                                                  source_kind="extracted")
                        allf = c2 + [x for x in cand2 if x not in c2]
                        findings.append(_finding(
                            "forensics", "archive-recurse",
                            f"nested flags: {', '.join(allf[:10])}", 0.85,
                            "bounded stdlib recursion into nested archives",
                            ["verify flag context"], allf, "candidate", allf[:10]))
                else:
                    if "encrypt" in msg.lower():
                        findings.append(_finding(
                            "forensics", "archive-recurse",
                            f"archive encrypted; no extraction attempted ({msg[:160]})", 0.7,
                            "password required; defaults only, no brute-force",
                            ["supply --password from challenge clues"], [], "candidate", [msg[:300]]))
                import shutil as _sh
                _sh.rmtree(tmpws, ignore_errors=True)
            except Exception as e:
                findings.append(_finding(
                    "forensics", "archive-recurse", f"nested scan skipped: {e}", 0.3,
                    "bounded recursion guarded", [], [], "inconclusive", [str(e)]))
        except Exception as e:
            findings.append(_finding(
                "forensics", "archive-inspect", f"archive survey failed: {e}", 0.3,
                "guarded dispatch", [], [], "inconclusive", [str(e)]))
    elif ftype == "image" and b.can_continue():
        findings.append(_finding(
            "forensics", "image-quick",
            "image: checked magic/dimensions/embedded flags; use stego helpers for depth",
            0.5, "low-cost image path only; no heavy carving here",
            ["ctf forensics stego <file>", "ctf forensics metadata <file>"],
            [], "candidate", [f"magic={magic_str}"]))
    elif ftype == "audio" and b.can_continue():
        try:
            from .audio import analyze as audio_analyze
            af, aarts, arender = audio_analyze(str(p), b)
            for f in af[:8]:
                findings.append(f)
            for a in (aarts or [])[:8]:
                try:
                    if Path(a.path) != p and b.consume_artifact(a.size):
                        artifacts.append(a)
                except Exception:
                    continue
        except Exception as e:
            findings.append(_finding(
                "forensics", "audio-quick", f"audio helper failed: {e}", 0.3,
                "guarded", ["ctf forensics stego <file>"], [], "inconclusive", [str(e)]))
    elif ftype == "document" and b.can_continue():
        try:
            from .documents import analyze as doc_analyze
            df, darts, _dr = doc_analyze(str(p), b)
            for f in df[:8]:
                findings.append(f)
            for a in (darts or [])[:8]:
                try:
                    if Path(a.path) != p and b.consume_artifact(a.size):
                        artifacts.append(a)
                except Exception:
                    continue
        except Exception as e:
            findings.append(_finding(
                "forensics", "document-quick", f"document helper failed: {e}", 0.3,
                "guarded", ["ctf forensics metadata <file>"], [], "inconclusive", [str(e)]))
    elif ftype == "disk" and b.can_continue():
        try:
            from .disk import analyze as disk_analyze
            df, darts, _dr = disk_analyze(str(p), b)
            for f in df[:8]:
                findings.append(f)
            for a in (darts or [])[:8]:
                try:
                    if Path(a.path) != p and b.consume_artifact(a.size):
                        artifacts.append(a)
                except Exception:
                    continue
        except Exception as e:
            findings.append(_finding(
                "forensics", "disk-quick", f"disk helper failed: {e}", 0.3,
                "guarded; read-only survey only",
                ["mmls <image>; fsstat <image>; bounded fls; icat chosen inode only"],
                [], "inconclusive", [str(e)]))
    elif ftype == "memory" and b.can_continue():
        try:
            from .memory import analyze as mem_analyze
            mf, marts, _mr = mem_analyze(str(p), b)
            for f in mf[:8]:
                findings.append(f)
            for a in (marts or [])[:8]:
                try:
                    if Path(a.path) != p and b.consume_artifact(a.size):
                        artifacts.append(a)
                except Exception:
                    continue
        except Exception as e:
            findings.append(_finding(
                "forensics", "memory-quick", f"memory helper failed: {e}", 0.3,
                "guarded; volatility first only",
                ["vol -f <dump> windows.info first; then one applicable plugin"],
                [], "inconclusive", [str(e)]))
    elif ftype in ("text", "binary") and b.can_continue():
        hint = ("text: readable content scanned; try crypto/metadata paths" if ftype == "text"
                else "binary: no archive/image/audio/document/pcap signature; try strings/metadata/crypto paths")
        findings.append(_finding(
            "forensics", f"{ftype}-quick", hint, 0.4,
            "low-cost fallback; no heavy carving here",
            ["ctf forensics strings <file>", "ctf forensics evidence <file>",
             "ctf crypto analyze \"<copied text>\" if encoded"],
            [], "inconclusive", [f"type={ftype}"]))
    elif ftype == "pcap" and b.can_continue():
        if which("tshark"):
            try:
                from .pcap import summarize as pcap_sum
                summ = pcap_sum(str(p), budget=b)[:3000]
                findings.append(_finding(
                    "forensics", "pcap-quick", _cap(summ, b)[:2000], 0.7,
                    "tshark summary for protocols/DNS/HTTP",
                    ["open in Wireshark for stream reconstruction"], [], "detected", [summ[:500]]))
            except Exception as e:
                findings.append(_finding(
                    "forensics", "pcap-quick", f"pcap helper failed: {e}", 0.3,
                    "guarded", ["open in Wireshark"], [], "inconclusive", [str(e)]))
        else:
            findings.append(_finding(
                "forensics", "pcap-quick", "pcap detected; tshark not installed",
                0.5, "capture needs protocol summary",
                ["open in Wireshark; ctf forensics pcap <file> when tshark exists"],
                [], "candidate", [f"magic={magic_str}"]))

    # 8. crypto analyze when structurally plausible
    stripped = u8.strip()
    plausible = bool(stripped) and 8 <= len(stripped) <= 10000 and b.can_continue()
    if plausible:
        b64ish = bool(re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped)) and len(re.sub(r"\s", "", stripped)) >= 32
        hexish = bool(re.fullmatch(r"(?:0x)?[0-9a-fA-F\s:,-]+", stripped)) and len(re.sub(r"[^0-9a-fA-F]", "", stripped)) >= 16
        Kw = ("base64" in joined.lower() or "==" in stripped[-4:] or b64ish or hexish
              or any(len(x) > 32 and set(x) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") for x in stripped.split()))
        if Kw:
            try:
                from ..crypto.auto import analyze_target
                out = analyze_target(stripped, description=description, max_depth=4)
                out_c = _cap(out, b)[:3000]
                cfl = find_flags(out)
                findings.append(_finding(
                    "crypto", "auto", out_c, 0.6 if not cfl else 0.85,
                    "bounded layered-decode probe (max_depth<=4)",
                    ["ctf crypto analyze \"<text>\" for depth"] + (["verify decoded flag"] if cfl else []),
                    cfl, "candidate" if not cfl else "solved", [out_c[:500]]))
            except Exception as e:
                findings.append(_finding(
                    "crypto", "auto", f"crypto probe skipped: {e}", 0.2,
                    "guarded; bounded probe only", [], [], "inconclusive", [str(e)]))

    # render
    lines = ["FORENSIC TRIAGE (pipeline)", "==========================",
             f"Input: {p}", f"Type: {ftype} | magic={magic_str} | ext={suffix or '(none)'}",
             f"Size: {size} bytes | sha256={sha} | entropy={ent}", ""]
    if file_out:
        lines += ["[file]", file_out.strip(), ""]
    lines += ["[findings]"]
    for f in findings:
        lines.append(f"- [{f.status}/{f.category}] ({f.tool}, conf={f.confidence}): {f.observation[:400]}")
        if f.flags:
            lines.append(f"    flags: {', '.join(f.flags[:5])}")
        if f.next_actions:
            lines.append(f"    next: {'; '.join(f.next_actions[:3])}")
    lines += ["", f"Artifacts: {len(artifacts)}", f"Budget: {b.profile} remaining={b.remaining:.1f}s"]
    render = _cap("\n".join(lines), b)
    return findings, artifacts, render

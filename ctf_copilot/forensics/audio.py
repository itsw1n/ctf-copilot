"""Audio analyzer: metadata/strings/appended-content, bounded spectrogram."""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

from ..analysis.budget import AnalysisBudget
from ..analysis.models import Artifact, Finding
from ..analysis.runner import artifact_for
from ..shared.files import printable_strings
from ..shared.flags import find_flags_bytes
from ..shared.tooling import run_tool, which


def _budget_or_default(budget):
    if budget is not None:
        return budget
    return AnalysisBudget.named("balanced")


def _timeout(b) -> int:
    try:
        rem = float(b.remaining)
    except Exception:
        rem = 45.0
    return max(1, min(45, int(rem) if rem > 0 else 45))


def _finding(category, tool, observation, confidence=0.5, why="", actions=None,
             flags=None, status="candidate", evidence=None, technique=""):
    return Finding(category, tool, observation, confidence, why, actions or [],
                   flags or [], technique, status, evidence or [])


EMBEDDED_SIGS = (
    (b"PK\x03\x04", "ZIP"), (b"%PDF-", "PDF"), (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"), (b"ID3", "MP3-ID3"),
)


def analyze(path, budget=None) -> tuple[list, list, str]:
    b = _budget_or_default(budget)
    p = Path(str(path))
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    if not p.is_file():
        f = _finding("forensics", "audio", f"Not a file: {p}", 1.0, "input missing",
                     [], [], "inconclusive", [str(p)])
        return [f], [], f"Not a file: {p}"
    try:
        artifacts.append(artifact_for(str(p), kind="file", source="audio", depth=0))
        size = p.stat().st_size
        data = p.read_bytes()[:8000000]
    except OSError as e:
        f = _finding("forensics", "audio", f"cannot read input: {e}", 0.9, str(e),
                     [], [], "inconclusive", [str(p)])
        return [f], artifacts, f"cannot read input: {e}"
    lines = ["AUDIO TRIAGE", "============", f"Input: {p} size={size}"]
    # metadata helpers if present
    for tool, args in (("soxi", ["soxi", str(p)]),
                       ("mediainfo", ["mediainfo", str(p)]),
                       ("file", ["file", str(p)])):
        if which(tool) and b.can_continue():
            _rc, txt = run_tool(args, timeout=_timeout(b), max_output=20000)
            snippet = (txt or "(no output)")[:2000]
            lines += ["", f"[{tool}]", snippet]
            findings.append(_finding("forensics", tool, snippet[:1000], 0.55,
                                     "audio metadata/channels/sample-rate",
                                     ["compare duration vs size for hidden data"], [], "detected", [snippet[:300]]))
    # strings / flags
    strs = printable_strings(data)[:500]
    flags = find_flags_bytes(data)
    if flags:
        findings.append(_finding("forensics", "audio-flags", f"flag-like strings: {', '.join(flags[:5])}", 0.7,
                                 "readable text in audio bytes", ["verify context"], flags, "candidate", flags[:5]))
    # appended-content check: embedded sig beyond small header
    hits = []
    for sig, name in EMBEDDED_SIGS:
        idx = data.find(sig, 16)
        if idx > 0:
            # skip self-match for MP3 ID3 at 0
            hits.append((idx, name))
    hits.sort()
    if hits:
        desc = "; ".join(f"{n}@{o}" for o, n in hits[:8])
        findings.append(_finding("forensics", "audio-appended",
                                 f"appended/embedded content suspected: {desc}", 0.8,
                                 "data beyond audio header suggests trailing archive/image",
                                 ["carve trailing bytes; ctf forensics recurse <file>"], [], "detected", [desc]))
        lines += ["", f"[appended] {desc}"]
    else:
        findings.append(_finding("forensics", "audio-appended", "no appended ZIP/PDF/PNG/JPEG signature beyond header", 0.35,
                                 "bounded signature scan", ["inspect spectrogram if morse/SSTV suspected"], [], "inconclusive", ["sig-scan"]))
    # SoX spectrogram: guidance, artifact only within budget
    if which("sox"):
        if b.can_continue(size=1024):
            try:
                out = Path(tempfile.mkdtemp(prefix="ctf-audio-")) / "spectrogram.png"

                def _cleanup_tmp():
                    try:
                        if out.is_file():
                            out.unlink()
                        out.parent.rmdir()
                    except Exception:
                        pass

                _rc, txt = run_tool(["sox", str(p), "-n", "spectrogram", "-o", str(out)],
                                    timeout=_timeout(b), max_output=20000)
                if out.is_file() and out.stat().st_size > 0 and out.stat().st_size <= b.max_file_bytes:
                    if b.consume_artifact(out.stat().st_size):
                        art = artifact_for(str(out), kind="image", source="sox-spectrogram", depth=1)
                        art.source_artifact = str(p)
                        artifacts.append(art)
                        findings.append(_finding("forensics", "sox-spectrogram",
                                                 f"spectrogram saved: {out}", 0.6,
                                                 "bounded SoX render within budget",
                                                 ["inspect spectrogram for hidden text/images"], [], "detected", [str(out)]))
                        lines += ["", f"[spectrogram] {out}"]
                    else:
                        _cleanup_tmp()
                        lines += ["", "[spectrogram] skipped: budget exhausted"]
                else:
                    _cleanup_tmp()
                    findings.append(_finding("forensics", "sox-spectrogram", "sox spectrogram produced no output", 0.3,
                                             "guarded", ["inspect manually: sox <file> -n spectrogram -o out.png"], [], "inconclusive", [txt[:200]]))
            except Exception as e:
                try:
                    if "out" in locals():
                        if out.is_file():
                            out.unlink()
                        out.parent.rmdir()
                except Exception:
                    pass
                findings.append(_finding("forensics", "sox-spectrogram", f"spectrogram skipped: {e}", 0.3,
                                         "guarded", ["sox <file> -n spectrogram -o out.png"], [], "inconclusive", [str(e)]))
        else:
            lines += ["", "[spectrogram] skipped: budget exhausted; guidance: sox <file> -n spectrogram -o out.png"]
            findings.append(_finding("forensics", "sox-spectrogram", "spectrogram guidance only (budget)", 0.4,
                                     "never exceed budget", ["sox <file> -n spectrogram -o out.png"], [], "inconclusive", ["budget"]))
    else:
        findings.append(_finding("forensics", "sox-spectrogram", "SoX not installed; spectrogram guidance only", 0.4,
                                 "visual hidden-data check",
                                 ["install sox; run: sox <file> -n spectrogram -o out.png; inspect for text/images"],
                                 [], "inconclusive", ["sox-missing"]))
    return findings, artifacts, "\n".join(lines)

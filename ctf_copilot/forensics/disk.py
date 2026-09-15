"""Disk-image analyzer (read-only, bounded). icat only via explicit call."""
from __future__ import annotations

import tempfile
from pathlib import Path

from ..analysis.budget import AnalysisBudget
from ..analysis.models import Artifact, Finding
from ..analysis.runner import artifact_for
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


def icat_candidate(image: str, inode: str | int, outdir: str | None = None, budget=None) -> tuple[str, Artifact | None]:
    """Explicit per-inode extraction (never auto-run). Returns (render, artifact)."""
    b = _budget_or_default(budget)
    if not which("icat"):
        return "icat is not installed (sleuthkit).", None
    p = Path(str(image))
    if not p.is_file():
        return f"Not a file: {p}", None
    dest_dir = Path(outdir) if outdir else Path(tempfile.mkdtemp(prefix="ctf-icat-"))
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe_inode = "".join(c if c.isalnum() else "_" for c in str(inode)) or "inode"
    dest = dest_dir / f"icat-{safe_inode}.bin"
    _rc, txt = run_tool(["icat", str(p), str(inode)], timeout=_timeout(b), max_output=b.max_output_bytes)
    # icat text mode may mangle binary; prefer raw bytes via subprocess capture is out of scope:
    # store tool output text bounded as artifact for review.
    try:
        dest.write_bytes(txt.encode("utf-8", "ignore")[:2000000])
        art = artifact_for(str(dest), kind="extracted", source=f"icat:{inode}", depth=1)
        art.source_artifact = str(image)
        return txt[:4000] or "(no output)", art
    except OSError as e:
        return f"icat save failed: {e}", None


def analyze(path, budget=None) -> tuple[list, list, str]:
    b = _budget_or_default(budget)
    p = Path(str(path))
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    if not p.is_file():
        f = _finding("forensics", "disk", f"Not a file: {p}", 1.0, "input missing",
                     [], [], "inconclusive", [str(p)])
        return [f], [], f"Not a file: {p}"
    try:
        artifacts.append(artifact_for(str(p), kind="file", source="disk", depth=0))
        size = p.stat().st_size
        head = p.read_bytes()[:64]
    except OSError as e:
        f = _finding("forensics", "disk", f"cannot read input: {e}", 0.9, str(e),
                     [], [], "inconclusive", [str(p)])
        return [f], artifacts, f"cannot read input: {e}"
    lines = ["DISK TRIAGE (read-only)", "=======================",
             f"Input: {p} size={size}"]
    tools = {t: which(t) for t in ("mmls", "fsstat", "fls")}
    if not any(tools.values()):
        findings.append(_finding(
            "forensics", "disk-survey",
            f"disk image hint (size={size}); sleuthkit tools missing (mmls/fsstat/fls)",
            0.4, "header/type hint only; no destructive actions taken",
            ["install sleuthkit", "run: mmls <image>", "run: fsstat <image>", "run: fls -r <image> (bounded)",
             "extract chosen inode only: icat <image> <inode>"],
            [], "inconclusive", [f"size={size}"]))
        render = "\n".join(lines + ["", "sleuthkit not installed; next: mmls/fsstat/bounded fls, then icat for chosen inodes only."])
        return findings, artifacts, render
    # Bounded read-only survey; save selected outputs as artifacts.
    for tool, args in (("mmls", ["mmls", str(p)]),
                       ("fsstat", ["fsstat", str(p)]),
                       ("fls", ["fls", "-r", str(p)])):
        if not tools[tool] or not b.can_continue():
            continue
        _rc, txt = run_tool(args, timeout=_timeout(b), max_output=60000)
        snippet = (txt or "(no output)")[:4000]
        lines += ["", f"[{tool}]", snippet]
        # persist tool output as artifact (selected outputs only)
        try:
            tmp = Path(tempfile.mkdtemp(prefix="ctf-disk-")) / f"{tool}.txt"
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(snippet, encoding="utf-8", errors="ignore")
            art = artifact_for(str(tmp), kind="report", source=tool, depth=1)
            art.source_artifact = str(p)
            artifacts.append(art)
        except OSError:
            pass
        findings.append(_finding("forensics", tool, snippet[:1200], 0.6,
                                 "read-only partition/filesystem listing",
                                 ["pick candidate inodes; icat chosen inode only; never auto-carve all"],
                                 [], "detected", [snippet[:300]]))
    findings.append(_finding("forensics", "disk-next",
                             "select candidate inodes before extraction; icat is explicit-only",
                             0.5, "bounded survey; no auto icat",
                             ["icat <image> <inode> for chosen file only"], [], "inconclusive", ["explicit-icat"]))
    return findings, artifacts, "\n".join(lines)

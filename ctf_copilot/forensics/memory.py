"""Memory-dump analyzer: plausible-dump check, bounded volatility-first."""
from __future__ import annotations

from pathlib import Path

from ..analysis.budget import AnalysisBudget
from ..analysis.models import Artifact, Finding
from ..analysis.runner import artifact_for
from ..shared.files import printable_strings
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


def _vol_binary() -> str | None:
    for name in ("vol", "volatility", "volatility3", "vol.py"):
        if which(name):
            return name
    return None


APPLICABLE_PLUGINS = [
    "windows.info", "windows.pslist", "windows.netscan", "windows.cmdline",
    "linux.pslist", "linux.bash", "mac.pslist",
]


def _plausible_dump(size: int, data: bytes) -> tuple[bool, str]:
    strs = printable_strings(data[:200000])[:500]
    blob = "\n".join(strs).lower()
    hints = [k for k in ("windows", "linux", "_eprocess", "pslist", "kernel", "ntoskrnl", "elf") if k in blob]
    # plausible if reasonably large or carries OS hints
    if size >= 1_000_000 or hints:
        return True, f"size={size} hints={','.join(hints) or 'none'}"
    return False, f"size={size} hints=none (small, no OS strings)"


def analyze(path, budget=None) -> tuple[list, list, str]:
    b = _budget_or_default(budget)
    p = Path(str(path))
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    if not p.is_file():
        f = _finding("forensics", "memory", f"Not a file: {p}", 1.0, "input missing",
                     [], [], "inconclusive", [str(p)])
        return [f], [], f"Not a file: {p}"
    try:
        artifacts.append(artifact_for(str(p), kind="file", source="memory", depth=0))
        size = p.stat().st_size
        data = p.read_bytes()[:300000]
    except OSError as e:
        f = _finding("forensics", "memory", f"cannot read input: {e}", 0.9, str(e),
                     [], [], "inconclusive", [str(p)])
        return [f], artifacts, f"cannot read input: {e}"
    plausible, reason = _plausible_dump(size, data)
    lines = ["MEMORY TRIAGE", "=============", f"Input: {p} {reason}"]
    vol = _vol_binary()
    if not vol:
        findings.append(_finding(
            "forensics", "memory-survey",
            f"memory-dump hint ({reason}); volatility not installed",
            0.4, "size+strings heuristic only; no plugins auto-run",
            ["install volatility3", "run: vol -f <dump> windows.info first",
             "then only applicable plugin: vol -f <dump> windows.pslist / windows.netscan / linux.pslist",
             "never auto-run all plugins"],
            [], "inconclusive", [reason]))
        render = "\n".join(lines + ["", "Next: volatility windows.info first, then one applicable plugin (bounded)."])
        return findings, artifacts, render
    # Volatility present: windows.info first, bounded.
    if b.can_continue():
        _rc, txt = run_tool([vol, "-f", str(p), "windows.info"], timeout=_timeout(b), max_output=60000)
        snippet = (txt or "(no output)")[:4000]
        lines += ["", "[windows.info]", snippet]
        findings.append(_finding("forensics", "volatility-windows.info", snippet[:1500], 0.7,
                                 "OS/profile baseline before any other plugin",
                                 [f"run one applicable plugin only, e.g. {vol} -f <dump> windows.pslist"],
                                 [], "detected", [snippet[:300]]))
        lines += ["", "Applicable bounded plugins (not auto-run): " + ", ".join(APPLICABLE_PLUGINS)]
        findings.append(_finding("forensics", "memory-next",
                                 "applicable plugins listed; run one at a time within budget", 0.5,
                                 "never auto-run all plugins",
                                 [f"{vol} -f <dump> {plug}" for plug in APPLICABLE_PLUGINS[:4]],
                                 [], "inconclusive", APPLICABLE_PLUGINS[:4]))
    else:
        findings.append(_finding("forensics", "memory-survey", "budget exhausted before volatility", 0.4,
                                 "bounded", [], [], "inconclusive", [reason]))
    if not plausible:
        findings.append(_finding("forensics", "memory-plausibility",
                                 f"weak dump plausibility ({reason}); verify file is a memory image", 0.3,
                                 "size+strings hint", ["confirm acquisition method"], [], "inconclusive", [reason]))
    return findings, artifacts, "\n".join(lines)

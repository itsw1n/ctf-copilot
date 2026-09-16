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


def _infer_os(data: bytes) -> str:
    """OS-aware hint: windows/linux/mac from strings (bounded, heuristic only)."""
    try:
        strs = printable_strings(data[:200000])[:500]
    except Exception:
        return "unknown"
    blob = "\n".join(strs).lower()
    win_hits = sum(1 for k in ("windows", "_eprocess", "ntoskrnl", "pslist") if k in blob)
    lin_hits = sum(1 for k in ("linux", "elf", "/proc/", "vmlinux") if k in blob)
    mac_hits = sum(1 for k in ("mac os", "darwin", "mach-o", "__dyld") if k in blob)
    scores = {"windows": win_hits, "linux": lin_hits, "mac": mac_hits}
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] > 0 else "unknown"


def _plausible_dump(size: int, data: bytes) -> tuple[bool, str]:
    strs = printable_strings(data[:200000])[:500]
    blob = "\n".join(strs).lower()
    hints = [k for k in ("windows", "linux", "_eprocess", "pslist", "kernel", "ntoskrnl", "elf") if k in blob]
    os_hint = _infer_os(data)
    # plausible if reasonably large or carries OS hints
    if size >= 1_000_000 or hints:
        return True, f"size={size} hints={','.join(hints) or 'none'} os={os_hint}"
    return False, f"size={size} hints=none os={os_hint} (small, no OS strings)"


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
    # Volatility present: OS-aware baseline first, bounded.
    os_hint = _infer_os(data)
    first_plugin = {"windows": "windows.info", "linux": "linux.pslist",
                    "mac": "mac.pslist"}.get(os_hint, "windows.info")
    if b.can_continue():
        _rc, txt = run_tool([vol, "-f", str(p), first_plugin], timeout=_timeout(b), max_output=60000)
        snippet = (txt or "(no output)")[:4000]
        lines += [f"", f"[{first_plugin}] (os hint: {os_hint})", snippet]
        findings.append(_finding("forensics", f"volatility-{first_plugin}", snippet[:1500], 0.7,
                                 f"OS-aware baseline ({os_hint}) before any other plugin; windows.info remains the windows baseline",
                                 [f"run one applicable plugin only, e.g. {vol} -f <dump> windows.pslist"],
                                 [], "detected", [snippet[:300], f"os={os_hint}"]))
        # Keep windows.info marker for windows/unknown baselines and correlation.
        if first_plugin != "windows.info":
            lines += ["", "Baseline note: for Windows dumps use windows.info first; volatility windows.info"]
        else:
            lines += ["", "Baseline note: volatility windows.info"]
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

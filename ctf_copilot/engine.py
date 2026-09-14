"""Offline evidence and recommendation engine used by ``ctf solve``.

The engine deliberately contains no model or network policy.  An action is a
small, explainable observation; category modules can add richer actions later.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re
from typing import Any

from .shared.flags import find_flags


@dataclass
class Finding:
    category: str
    tool: str
    observation: str
    confidence: float = 0.5
    why: str = ""
    next_actions: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


@dataclass
class Artifact:
    path: str
    kind: str
    source: str = ""


@dataclass
class Hypothesis:
    name: str
    category: str
    evidence: list[str] = field(default_factory=list)
    score: float = 0.0
    suggested_command: str = ""


@dataclass
class Action:
    command: str
    tool: str
    purpose: str
    cost: int = 1
    risk: str = "safe"


@dataclass
class SolveReport:
    target: str
    category: str
    description: str = ""
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    status: str = "incomplete"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> Path:
        p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return p


def extract_flag_pattern(pattern: str | None) -> re.Pattern[str] | None:
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid flag pattern: {exc}") from exc


def collect_flags(text: str, pattern: str | None = None) -> list[str]:
    found = find_flags(text)
    custom = extract_flag_pattern(pattern)
    if custom:
        for match in custom.finditer(text):
            found.append(match.group(0))
    return list(dict.fromkeys(found))


def classify_target(target: str) -> str:
    from .solve import classify_file
    p = Path(target)
    if p.is_dir(): return "forensics"
    if p.is_file(): return classify_file(p).split('/')[0]
    if target.startswith(("http://", "https://")): return "web"
    return "crypto"


def initial_report(target: str, description: str = "", flag_pattern: str | None = None) -> SolveReport:
    category = classify_target(target)
    report = SolveReport(target=target, category=category, description=description)
    context = description or target
    flags = collect_flags(context, flag_pattern)
    if flags:
        report.flags = flags; report.status = "flag-found"
        report.findings.append(Finding(category, "flag scanner", "Flag-like value found in input", 1.0, "The value matches a configured flag pattern", flags=flags))
        return report
    report.findings.append(Finding(category, "built-in classifier", f"Target classified as {category}", 0.85, "Category determines the safest first-pass playbook"))
    if category == "web":
        report.actions = [Action(f"ctf web analyze {target}", "built-in HTTP client", "Inspect status, forms, scripts, cookies, and endpoint clues"), Action(f"ctf web endpoints {target}", "endpoint extractor", "Find API and hidden route references")]
        report.hypotheses = [Hypothesis("source or endpoint clue", "web", ["URL target"], .7, report.actions[0].command)]
    elif category in {"forensics", "generic-file", "text"}:
        report.actions = [Action(f"ctf forensics triage {target}", "built-in file triage", "Check signatures, strings, metadata, and embedded clues"), Action(f"ctf flags scan {target}", "flag scanner", "Search recursively for flag-like strings")]
        report.hypotheses = [Hypothesis("hidden file or embedded clue", "forensics", ["file or directory target"], .75, report.actions[0].command)]
    else:
        report.actions = [Action(f"ctf crypto analyze {target}", "crypto analyzer", "Identify and reverse common encodings and ciphers"), Action(f"ctf flags scan {target}", "flag scanner", "Search text for flag-like strings")]
        report.hypotheses = [Hypothesis("encoding or classical cipher", "crypto", ["text-like target"], .7, report.actions[0].command)]
    return report


def render_report(report: SolveReport) -> str:
    lines = ["CTF SOLVE - EVIDENCE REPORT", "===========================", f"Target: {report.target}", f"Category: {report.category}", f"Status: {report.status}"]
    if report.description: lines += [f"Description: {report.description[:500]}"]
    for f in report.findings:
        lines += ["", f"FINDING [{f.confidence:.0%}]", f"  Tool used: {f.tool}", f"  What it checked: {f.observation}"]
        if f.why: lines.append(f"  Why it matters: {f.why}")
        if f.flags: lines += ["  Possible flags:"] + [f"    {x}" for x in f.flags]
    if report.actions:
        lines += ["", "NEXT SUGGESTED ACTIONS"]
        for a in sorted(report.actions, key=lambda x: (x.cost, x.risk)):
            lines.append(f"  - {a.command}  ({a.tool}: {a.purpose})")
    if not report.flags:
        lines += ["", "No flag found in the first pass.", "You could use `ctf tools --doctor` to see available tools to dig deeper."]
    return "\n".join(lines)

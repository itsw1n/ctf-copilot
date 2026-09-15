from __future__ import annotations

from collections import deque
import hashlib
from pathlib import Path
import time
from typing import Any

from .budget import AnalysisBudget
from .models import Action, Artifact, SolveReport
from .registry import AnalyzerRegistry


def artifact_for(path: str | Path, kind: str = "file", source: str = "", depth: int = 0) -> Artifact:
    target = Path(path)
    data = target.read_bytes() if target.is_file() else str(target).encode()
    digest = hashlib.sha256(data).hexdigest()
    return Artifact(str(target), kind, source, f"artifact-{digest[:12]}", kind, len(data), digest, source, depth)


def run_queue(initial: list[tuple[Any, Artifact]], registry: AnalyzerRegistry,
              report: SolveReport, budget: AnalysisBudget, category: str | None = None) -> SolveReport:
    queue = deque(initial)
    seen: set[tuple[str, str]] = set()
    while queue and budget.can_continue():
        value, artifact = queue.popleft()
        identity = (artifact.sha256 or hashlib.sha256(repr(value).encode()).hexdigest(), artifact.kind)
        if identity in seen or artifact.depth > budget.max_depth:
            continue
        seen.add(identity)
        if not budget.consume_artifact(artifact.size):
            report.stop_reason = "artifact or byte budget exhausted"
            break
        report.artifacts.append(artifact)
        for score, analyzer in registry.applicable(value, {"budget": budget, "artifact": artifact}, category):
            if not budget.can_continue():
                break
            started = time.monotonic()
            action = Action(analyzer.name, analyzer.name, f"Analyze {artifact.path}", analyzer.cost, analyzer.risk, analyzer.name, "running")
            try:
                findings, artifacts = analyzer.analyze(value, {"budget": budget, "artifact": artifact})
                report.findings.extend(findings)
                action.status = "complete"
                for child in artifacts:
                    child.depth = max(child.depth, artifact.depth + 1)
                    queue.append((Path(child.path) if child.path else child, child))
            except Exception as exc:
                action.status = "error"
                action.purpose += f": {exc}"
            action.duration = round(time.monotonic() - started, 3)
            budget.actions += 1
            report.actions.append(action)
    if not report.stop_reason:
        report.stop_reason = "no supported action remains" if not queue else "time budget exhausted"
    report.budget = budget.snapshot()
    report.usage = budget.usage()
    return report

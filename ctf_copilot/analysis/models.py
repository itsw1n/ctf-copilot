from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    # The first seven fields retain the v1.0 positional constructor contract.
    category: str
    tool: str
    observation: str
    confidence: float = 0.5
    why: str = ""
    next_actions: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    technique: str = ""
    status: str = "candidate"
    evidence: list[str] = field(default_factory=list)
    result: str = ""
    artifacts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class Artifact:
    # path/kind/source retain the v1.0 positional constructor contract.
    path: str
    kind: str
    source: str = ""
    id: str = ""
    media_type: str = ""
    size: int = 0
    sha256: str = ""
    source_artifact: str = ""
    depth: int = 0
    generated_by: str = ""


@dataclass
class Hypothesis:
    name: str
    category: str
    evidence: list[str] = field(default_factory=list)
    score: float = 0.0
    suggested_command: str = ""


@dataclass
class Action:
    # command/tool/purpose/cost/risk retain the v1.0 positional contract.
    command: str
    tool: str
    purpose: str
    cost: int = 1
    risk: str = "safe"
    analyzer: str = ""
    status: str = "pending"
    duration: float = 0.0


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
    flag_candidates: list[str] = field(default_factory=list)
    status: str = "incomplete"
    stop_reason: str = ""
    budget: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return target

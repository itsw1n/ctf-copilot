from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Candidate:
    kind: str
    output: str
    score: float
    confidence: float
    reason: str
    parameter: str | None = None
    structural_confidence: float = 0.0
    speculative: bool = False

@dataclass(frozen=True)
class PathResult:
    chain: tuple[Candidate, ...]
    output: str
    score: float

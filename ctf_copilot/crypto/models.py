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

@dataclass(frozen=True)
class PathResult:
    chain: tuple[Candidate, ...]
    output: str
    score: float

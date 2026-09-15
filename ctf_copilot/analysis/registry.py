from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .models import Artifact, Finding


class Analyzer(Protocol):
    name: str
    category: str
    cost: int
    risk: str

    def detect(self, value: Any, context: dict[str, Any]) -> float: ...
    def analyze(self, value: Any, context: dict[str, Any]) -> tuple[list[Finding], list[Artifact]]: ...


@dataclass
class FunctionAnalyzer:
    name: str
    category: str
    detector: Callable[[Any, dict[str, Any]], float]
    handler: Callable[[Any, dict[str, Any]], tuple[list[Finding], list[Artifact]]]
    cost: int = 1
    risk: str = "safe"

    def detect(self, value: Any, context: dict[str, Any]) -> float:
        return max(0.0, min(1.0, float(self.detector(value, context))))

    def analyze(self, value: Any, context: dict[str, Any]) -> tuple[list[Finding], list[Artifact]]:
        return self.handler(value, context)


class AnalyzerRegistry:
    def __init__(self) -> None:
        self._rows: list[Analyzer] = []

    def register(self, analyzer: Analyzer) -> Analyzer:
        self._rows.append(analyzer)
        return analyzer

    def applicable(self, value: Any, context: dict[str, Any], category: str | None = None) -> list[tuple[float, Analyzer]]:
        rows = []
        for analyzer in self._rows:
            if category and analyzer.category not in (category, "shared"):
                continue
            try:
                score = analyzer.detect(value, context)
            except Exception:
                score = 0.0
            if score > 0:
                rows.append((score, analyzer))
        return sorted(rows, key=lambda row: (row[0], -row[1].cost), reverse=True)

from __future__ import annotations

from dataclasses import dataclass, field
import time


PROFILES = {
    "fast": dict(seconds=30, max_depth=3, max_artifacts=75, max_total_bytes=96 << 20),
    "balanced": dict(seconds=120, max_depth=5, max_artifacts=200, max_total_bytes=256 << 20),
    "deep": dict(seconds=300, max_depth=7, max_artifacts=400, max_total_bytes=512 << 20),
}


@dataclass
class AnalysisBudget:
    profile: str = "balanced"
    seconds: int = 120
    max_depth: int = 5
    max_artifacts: int = 200
    max_total_bytes: int = 256 << 20
    max_file_bytes: int = 32 << 20
    max_archive_entries: int = 500
    max_output_bytes: int = 120_000
    actions: int = 0
    artifacts: int = 0
    total_bytes: int = 0
    requests: int = 0
    started: float = field(default_factory=time.monotonic)

    @classmethod
    def named(cls, profile: str = "balanced") -> "AnalysisBudget":
        if profile not in PROFILES:
            raise ValueError(f"unknown budget profile: {profile}")
        return cls(profile=profile, **PROFILES[profile])

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    @property
    def remaining(self) -> float:
        return max(0.0, self.seconds - self.elapsed)

    def can_continue(self, depth: int = 0, size: int = 0) -> bool:
        return (
            self.remaining > 0
            and depth <= self.max_depth
            and self.artifacts < self.max_artifacts
            and size <= self.max_file_bytes
            and self.total_bytes + size <= self.max_total_bytes
        )

    def consume_artifact(self, size: int) -> bool:
        if not self.can_continue(size=size):
            return False
        self.artifacts += 1
        self.total_bytes += size
        return True

    def snapshot(self) -> dict[str, int | float | str]:
        return {
            "profile": self.profile, "seconds": self.seconds,
            "max_depth": self.max_depth, "max_artifacts": self.max_artifacts,
            "max_total_bytes": self.max_total_bytes,
        }

    def usage(self) -> dict[str, int | float]:
        return {
            "elapsed_seconds": round(self.elapsed, 3), "actions": self.actions,
            "artifacts": self.artifacts, "total_bytes": self.total_bytes,
            "requests": self.requests,
        }

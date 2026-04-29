from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def _rank(self) -> int:
        return list(RiskLevel).index(self)

    def __lt__(self, other: RiskLevel) -> bool:
        return self._rank() < other._rank()

    def __le__(self, other: RiskLevel) -> bool:
        return self._rank() <= other._rank()

    def __gt__(self, other: RiskLevel) -> bool:
        return self._rank() > other._rank()

    def __ge__(self, other: RiskLevel) -> bool:
        return self._rank() >= other._rank()


@dataclass
class Match:
    rule_id: str
    pattern: str
    matched_text: str
    start: int
    end: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    text: str
    is_safe: bool
    risk_level: RiskLevel
    score: float
    matches: list[Match] = field(default_factory=list)
    guard_name: str = ""
    redacted: str | None = None

    @classmethod
    def safe(cls, text: str, guard_name: str = "") -> ScanResult:
        return cls(
            text=text,
            is_safe=True,
            risk_level=RiskLevel.SAFE,
            score=0.0,
            guard_name=guard_name,
        )


@dataclass
class GuardConfig:
    threshold: float = 0.5
    redact_pii: bool = True
    block_on_risk: RiskLevel = RiskLevel.HIGH
    rules_dir: str = ""
    custom_patterns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError(
                f"threshold must be between 0 and 1, got {self.threshold}"
            )
from __future__ import annotations
from prompt_guard.types import GuardConfig, RiskLevel, ScanResult
from prompt_guard.injection import InjectionGuard
from prompt_guard.jailbreak import JailbreakGuard
from prompt_guard.pii import PIIGuard


class Scanner:
    """Runs all guards and returns the highest risk result."""

    def __init__(self, config: GuardConfig | None = None) -> None:
        self.config = config or GuardConfig()
        self._guards = [
            InjectionGuard(self.config),
            JailbreakGuard(self.config),
            PIIGuard(self.config),
        ]

    def scan(self, text: str) -> ScanResult:
        results = [guard.scan(text) for guard in self._guards]

        # Collect all matches across all guards
        all_matches = [m for r in results for m in r.matches]

        if not all_matches:
            return ScanResult.safe(text, guard_name="scanner")

        # Pick the highest risk level and score across all guards
        highest_risk = max(r.risk_level for r in results)
        highest_score = max(r.score for r in results)
        is_safe = highest_risk < self.config.block_on_risk

        # Use redacted text from PII guard if available
        redacted = next((r.redacted for r in results if r.redacted), None)

        return ScanResult(
            text=text,
            is_safe=is_safe,
            risk_level=highest_risk,
            score=highest_score,
            matches=all_matches,
            guard_name="scanner",
            redacted=redacted,
        )
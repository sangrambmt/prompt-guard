from __future__ import annotations
import json
import re
from pathlib import Path
from prompt_guard.types import GuardConfig, Match, RiskLevel, ScanResult

_RISK_MAP = {
    "safe": RiskLevel.SAFE,
    "low": RiskLevel.LOW,
    "medium": RiskLevel.MEDIUM,
    "high": RiskLevel.HIGH,
    "critical": RiskLevel.CRITICAL,
}

_RULES_DIR = Path(__file__).parent.parent / "rules"


class PIIGuard:
    """Detects and redacts PII from input text."""

    def __init__(self, config: GuardConfig | None = None) -> None:
        self.config = config or GuardConfig()
        self._rules = self._load_rules()
        self._compiled = self._compile_rules()

    def scan(self, text: str) -> ScanResult:
        if not text or not text.strip():
            return ScanResult.safe(text, guard_name="pii")

        matches = self._find_matches(text)

        if not matches:
            return ScanResult.safe(text, guard_name="pii")

        risk_level = self._aggregate_risk(matches)
        score = self._aggregate_score(matches)
        is_safe = risk_level < self.config.block_on_risk
        redacted = self._redact(text, matches) if self.config.redact_pii else None

        return ScanResult(
            text=text,
            is_safe=is_safe,
            risk_level=risk_level,
            score=score,
            matches=matches,
            guard_name="pii",
            redacted=redacted,
        )

    def _load_rules(self) -> list[dict]:
        rules_dir = Path(self.config.rules_dir) if self.config.rules_dir else _RULES_DIR
        path = rules_dir / "pii.json"
        if not path.exists():
            return []
        with open(path) as f:
            return json.load(f)

    def _compile_rules(self) -> list[tuple]:
        compiled = []
        for rule in self._rules:
            try:
                compiled.append((rule, re.compile(rule["pattern"], re.IGNORECASE)))
            except re.error:
                pass
        return compiled

    def _find_matches(self, text: str) -> list[Match]:
        matches = []
        for rule, pattern in self._compiled:
            for m in pattern.finditer(text):
                matches.append(Match(
                    rule_id=rule["id"],
                    pattern=rule["pattern"],
                    matched_text=m.group(),
                    start=m.start(),
                    end=m.end(),
                    metadata={
                        "description": rule.get("description", ""),
                        "risk": rule.get("risk", "medium"),
                        "score": rule.get("score", 0.5),
                        "label": rule.get("label", "PII"),
                    },
                ))
        return matches

    def _redact(self, text: str, matches: list[Match]) -> str:
        # Sort matches in reverse order so offsets stay valid as we replace
        result = text
        for match in sorted(matches, key=lambda m: m.start, reverse=True):
            label = match.metadata.get("label", "PII")
            result = result[:match.start] + f"[{label}]" + result[match.end:]
        return result

    def _aggregate_risk(self, matches: list[Match]) -> RiskLevel:
        highest = RiskLevel.SAFE
        for m in matches:
            level = _RISK_MAP.get(m.metadata.get("risk", "medium"), RiskLevel.MEDIUM)
            if level > highest:
                highest = level
        return highest

    def _aggregate_score(self, matches: list[Match]) -> float:
        if not matches:
            return 0.0
        scores = [m.metadata.get("score", 0.5) for m in matches]
        return round(min(max(scores) + min(0.05 * (len(scores) - 1), 0.1), 1.0), 4)
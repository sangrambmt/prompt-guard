from __future__ import annotations
import json
import re
from abc import ABC, abstractmethod
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


class BaseGuard(ABC):
    def __init__(self, config: GuardConfig | None = None) -> None:
        self.config = config or GuardConfig()
        self._rules = self._load_rules()
        self._compiled = self._compile_rules()

    @property
    @abstractmethod
    def guard_name(self) -> str: ...

    @property
    @abstractmethod
    def rules_file(self) -> str: ...

    def scan(self, text: str) -> ScanResult:
        if not text or not text.strip():
            return ScanResult.safe(text, guard_name=self.guard_name)
        normalised = " ".join(text.split())
        matches = self._find_matches(normalised)
        matches += self._find_matches_raw(text)
        matches += self._scan_custom_patterns(normalised)
        if not matches:
            return ScanResult.safe(text, guard_name=self.guard_name)
        risk_level = self._aggregate_risk(matches)
        score = self._aggregate_score(matches)
        is_safe = risk_level < self.config.block_on_risk
        return ScanResult(
            text=text,
            is_safe=is_safe,
            risk_level=risk_level,
            score=score,
            matches=matches,
            guard_name=self.guard_name,
        )

    def _load_rules(self) -> list[dict]:
        rules_dir = Path(self.config.rules_dir) if self.config.rules_dir else _RULES_DIR
        path = rules_dir / self.rules_file
        if not path.exists():
            return []
        with open(path) as f:
            return json.load(f)

    def _compile_rules(self) -> list[tuple]:
        compiled = []
        for rule in self._rules:
            multiline = rule.get("multiline", False)
            flags = re.IGNORECASE | re.DOTALL | (re.MULTILINE if multiline else 0)
            try:
                compiled.append((rule, re.compile(rule["pattern"], flags), multiline))
            except re.error:
                pass
        return compiled

    def _find_matches(self, text: str) -> list[Match]:
        matches = []
        for rule, pattern, multiline in self._compiled:
            if multiline:
                continue
            for m in pattern.finditer(text):
                matches.append(self._make_match(rule, m))
        return matches

    def _find_matches_raw(self, text: str) -> list[Match]:
        matches = []
        for rule, pattern, multiline in self._compiled:
            if not multiline:
                continue
            for m in pattern.finditer(text):
                matches.append(self._make_match(rule, m))
        return matches

    def _make_match(self, rule: dict, m: re.Match) -> Match:
        return Match(
            rule_id=rule["id"],
            pattern=rule["pattern"],
            matched_text=m.group(),
            start=m.start(),
            end=m.end(),
            metadata={
                "description": rule.get("description", ""),
                "risk": rule.get("risk", "medium"),
                "score": rule.get("score", 0.5),
            },
        )

    def _scan_custom_patterns(self, text: str) -> list[Match]:
        matches = []
        for pat in self.config.custom_patterns:
            try:
                for m in re.compile(pat, re.IGNORECASE).finditer(text):
                    matches.append(Match(
                        rule_id="custom", pattern=pat,
                        matched_text=m.group(), start=m.start(), end=m.end(),
                        metadata={"risk": "high", "score": 0.8},
                    ))
            except re.error:
                pass
        return matches

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
import pytest
from prompt_guard import PIIGuard, GuardConfig, RiskLevel


@pytest.fixture
def guard():
    return PIIGuard()


class TestSafeInputs:
    def test_normal_text(self, guard):
        assert guard.scan("The weather is nice today.").is_safe is True

    def test_empty(self, guard):
        assert guard.scan("").is_safe is True


class TestDetection:
    def test_email(self, guard):
        result = guard.scan("Contact me at alice@example.com")
        assert len(result.matches) > 0
        assert any(m.rule_id == "pii.email" for m in result.matches)
        assert result.risk_level == RiskLevel.MEDIUM

    def test_ssn(self, guard):
        result = guard.scan("My SSN is 123-45-6789")
        assert result.risk_level >= RiskLevel.HIGH

    def test_credit_card(self, guard):
        result = guard.scan("My card is 4111 1111 1111 1111")
        assert result.is_safe is False

    def test_api_key(self, guard):
        result = guard.scan("My key is sk-abcdefghijklmnop")
        assert result.risk_level == RiskLevel.CRITICAL

    def test_multiple_pii(self, guard):
        result = guard.scan("Email: alice@example.com, SSN: 123-45-6789")
        assert len(result.matches) >= 2


class TestRedaction:
    def test_email_redacted(self, guard):
        result = guard.scan("Email me at alice@example.com")
        assert "[EMAIL]" in result.redacted
        assert "alice@example.com" not in result.redacted

    def test_ssn_redacted(self, guard):
        result = guard.scan("My SSN is 123-45-6789")
        assert "[SSN]" in result.redacted

    def test_no_redaction_when_disabled(self):
        config = GuardConfig(redact_pii=False)
        guard = PIIGuard(config)
        result = guard.scan("Email: alice@example.com")
        assert result.redacted is None
"""Tests for the LLM synthesis layer."""

from unittest.mock import Mock, patch

import pytest

from ovs_logs.core.analysis.indicators import SuspiciousIndicator
from ovs_logs.core.llm import (
    LLMProvider,
    LLMSynthesizer,
    OpenAICompatibleProvider,
    PromptBuilder,
    ResponseParser,
)
from ovs_logs.core.report import IncidentReport
from ovs_logs.core.threat_intel import ReputationResult


class FakeLLMProvider(LLMProvider):
    """Test provider that returns a fixed string."""

    def __init__(self, response: str) -> None:
        self.response = response

    def generate(self, prompt: str) -> str:
        return self.response


def test_provider_explicit_falsy_overrides_are_honored() -> None:
    """Explicit falsy values (0, "") must override settings defaults, not be discarded."""
    provider = OpenAICompatibleProvider(api_key="sk-test", endpoint="", model="", timeout=0)

    assert provider.endpoint == ""
    assert provider.model == ""
    assert provider.timeout == 0


def _sample_response() -> str:
    return """
```json
{
  "title": "Brute-force login attempt",
  "summary": "Multiple failed logins from a single IP.",
  "severity": "High",
  "timeline": [
    {"timestamp": "2024-01-01T00:00:00", "description": "Failed login",
     "source_ip": "1.2.3.4", "event_type": "POST", "status_code": 401,
     "raw_message": null}
  ],
  "mitre_mappings": [
    {"technique_id": "T1110", "technique_name": "Brute Force",
     "tactic": "Credential Access",
     "description": "Repeated failed auth attempts."}
  ],
  "mitigation": {
    "format": "Sigma",
    "title": "Detect repeated failed logins",
    "content": "title: repeated failed logins"
  },
  "indicators": [
    {"type": "top_talkers", "severity": "High",
     "description": "IP 1.2.3.4 generated 250 events",
     "evidence": {"source_ip": "1.2.3.4", "event_count": 250}}
  ],
  "metadata": {"source_file": "auth.log"}
}
```
"""


def test_prompt_builder_includes_indicators() -> None:
    indicators = [
        SuspiciousIndicator(
            type="top_talkers",
            severity="High",
            description="IP 1.2.3.4 generated 250 events",
            evidence={"source_ip": "1.2.3.4", "event_count": 250},
        )
    ]
    threat_intel = {"1.2.3.4": ReputationResult(ip="1.2.3.4", abuse_confidence_score=75, total_reports=10)}
    prompt = PromptBuilder().build(indicators, threat_intel, sample_events=[{"line": "POST /login 401"}])

    assert "IP 1.2.3.4 generated 250 events" in prompt
    assert "abuse confidence 75" in prompt
    assert "POST /login 401" in prompt


def test_response_parser_extracts_markdown_json() -> None:
    parser = ResponseParser()
    data = parser.parse(_sample_response())

    assert data["title"] == "Brute-force login attempt"
    assert data["severity"] == "High"
    assert len(data["timeline"]) == 1


def test_response_parser_extracts_raw_json() -> None:
    parser = ResponseParser()
    raw = (
        '{"title": "T", "summary": "S", "severity": "Low", "timeline": [], '
        '"mitre_mappings": [], "mitigation": {"format": "Sigma", "title": "T", '
        '"content": "C"}}'
    )
    data = parser.parse(raw)
    assert data["title"] == "T"


def test_response_parser_missing_fields_raises() -> None:
    parser = ResponseParser()
    with pytest.raises(ValueError, match="missing required fields"):
        parser.parse('{"title": "T"}')


def test_synthesizer_returns_incident_report() -> None:
    provider = FakeLLMProvider(_sample_response())
    synthesizer = LLMSynthesizer(provider)
    indicators = [
        SuspiciousIndicator(
            type="top_talkers",
            severity="High",
            description="IP 1.2.3.4 generated 250 events",
            evidence={"source_ip": "1.2.3.4", "event_count": 250},
        )
    ]

    report = synthesizer.synthesize(indicators)

    assert isinstance(report, IncidentReport)
    assert report.title == "Brute-force login attempt"
    assert report.severity == "High"
    assert report.mitigation.format == "Sigma"


def test_openai_provider_sends_request() -> None:
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"choices": [{"message": {"content": '{"title": "T"}'}}]}

    with patch("ovs_logs.core.llm.requests.post", return_value=mock_response) as mock_post:
        provider = OpenAICompatibleProvider(api_key="sk-test")
        result = provider.generate("hello")

    assert result == '{"title": "T"}'
    mock_post.assert_called_once()

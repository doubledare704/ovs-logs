"""Tests for the incident report schema."""

from typing import Any

import pytest

from ovs_logs.core.report import IncidentReport

from .conftest import sample_report


def test_incident_report_creation() -> None:
    report = sample_report()
    assert report.title == "Brute-force login attempt"
    assert report.severity == "High"
    assert len(report.timeline) == 1
    assert report.timeline[0].source_ip == "1.2.3.4"
    assert report.mitigation.format == "Sigma"


def test_incident_report_serialization_round_trip() -> None:
    report = sample_report()
    serialized = report.to_dict()
    restored = IncidentReport.from_dict(serialized)

    assert restored == report


def test_from_dict_tolerates_extra_timeline_fields() -> None:
    """Extra keys emitted by local LLMs (e.g. ``event_count``) must be dropped."""
    data: dict[str, Any] = {
        "title": "X",
        "summary": "X",
        "severity": "Low",
        "timeline": [
            {
                "timestamp": "2024-01-01T00:00:00",
                "description": "Failed login",
                "event_count": 250,
                "source": "some hallucinated key",
            }
        ],
        "mitre_mappings": [],
        "mitigation": {"format": "Sigma", "title": "T", "content": "C"},
        "indicators": [],
        "metadata": {},
    }
    report = IncidentReport.from_dict(data)

    assert report.timeline[0].timestamp == "2024-01-01T00:00:00"
    assert report.timeline[0].description == "Failed login"


def test_from_dict_tolerates_extra_nested_fields() -> None:
    """Unknown keys on mitre mappings, indicators, and mitigation are ignored."""
    data: dict[str, Any] = {
        "title": "X",
        "summary": "X",
        "severity": "Low",
        "timeline": [],
        "mitre_mappings": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Repeated failed auth.",
                "score": 9,
            }
        ],
        "mitigation": {
            "format": "Sigma",
            "title": "Detect repeated failed logins",
            "content": "title: repeated failed logins",
            "rule_id": 12345,
        },
        "indicators": [
            {
                "type": "top_talkers",
                "severity": "High",
                "description": "IP 1.2.3.4 generated 250 events",
                "evidence": {"source_ip": "1.2.3.4", "event_count": 250},
                "confidence": "high",
            }
        ],
        "metadata": {},
    }
    report = IncidentReport.from_dict(data)

    assert report.mitre_mappings[0].technique_id == "T1110"
    assert report.mitigation.format == "Sigma"
    assert report.indicators[0].evidence == {"source_ip": "1.2.3.4", "event_count": 250}


def test_from_dict_defaults_missing_indicator_evidence() -> None:
    """Local LLMs omitting required fields must get defaults, not a TypeError."""
    data: dict[str, Any] = {
        "title": "X",
        "summary": "X",
        "severity": "Low",
        "timeline": [],
        "mitre_mappings": [],
        "mitigation": {"format": "Sigma", "title": "T", "content": "C"},
        "indicators": [{"type": "top_talkers", "severity": "High", "description": "IP 1.2.3.4 generated 250 events"}],
        "metadata": {},
    }
    report = IncidentReport.from_dict(data)

    assert report.indicators[0].evidence == {}


def test_from_dict_defaults_missing_indicator_type_and_severity() -> None:
    """Indicators missing the required ``type`` key must not crash with a TypeError."""
    data: dict[str, Any] = {
        "title": "X",
        "summary": "X",
        "severity": "Low",
        "timeline": [],
        "mitre_mappings": [],
        "mitigation": {"format": "Sigma", "title": "T", "content": "C"},
        "indicators": [{"description": "LLM omitted the type and severity keys"}],
        "metadata": {},
    }
    report = IncidentReport.from_dict(data)

    indicator = report.indicators[0]
    assert indicator.type == "unknown"
    assert indicator.severity == "Medium"
    assert indicator.description == "LLM omitted the type and severity keys"
    assert indicator.evidence == {}


def test_from_dict_defaults_incomplete_mitre_and_mitigation() -> None:
    """Partially emitted mitre mappings and mitigation artifacts get defaults, not a TypeError."""
    data: dict[str, Any] = {
        "title": "X",
        "summary": "X",
        "severity": "Low",
        "timeline": [],
        "mitre_mappings": [{"tactic": "Credential Access"}],
        "mitigation": {"title": "Detect repeated failed logins"},
        "indicators": [],
        "metadata": {},
    }
    report = IncidentReport.from_dict(data)

    assert report.mitre_mappings[0].technique_id == "unknown"
    assert report.mitre_mappings[0].technique_name == ""
    assert report.mitigation.format == ""
    assert report.mitigation.content == ""


def test_invalid_severity_raises() -> None:
    data: dict[str, Any] = {
        "title": "X",
        "summary": "X",
        "severity": "Critical",
        "timeline": [],
        "mitre_mappings": [],
        "mitigation": {"format": "Sigma", "title": "T", "content": "C"},
        "indicators": [],
        "metadata": {},
    }
    with pytest.raises(ValueError, match="Incident severity must be"):
        IncidentReport.from_dict(data)

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

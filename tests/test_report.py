"""Tests for the incident report schema."""

from typing import Any

import pytest

from ovs_logs.core.analysis.indicators import SuspiciousIndicator
from ovs_logs.core.report import (
    IncidentReport,
    MitigationArtifact,
    MitreMapping,
    TimelineEvent,
)


def _sample_report() -> IncidentReport:
    return IncidentReport(
        title="Brute-force login attempt",
        summary="Multiple failed logins from a single IP.",
        severity="High",
        timeline=[
            TimelineEvent(
                timestamp="2024-01-01T00:00:00",
                description="Failed login",
                source_ip="1.2.3.4",
                event_type="POST",
                status_code=401,
            )
        ],
        mitre_mappings=[
            MitreMapping(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                description="Repeated failed authentication attempts.",
            )
        ],
        mitigation=MitigationArtifact(
            format="Sigma",
            title="Detect repeated failed logins",
            content="title: repeated failed logins",
        ),
        indicators=[
            SuspiciousIndicator(
                type="top_talkers",
                severity="High",
                description="IP 1.2.3.4 generated 250 events",
                evidence={"source_ip": "1.2.3.4", "event_count": 250},
            )
        ],
        metadata={"source_file": "auth.log"},
    )


def test_incident_report_creation() -> None:
    report = _sample_report()
    assert report.title == "Brute-force login attempt"
    assert report.severity == "High"
    assert len(report.timeline) == 1
    assert report.timeline[0].source_ip == "1.2.3.4"
    assert report.mitigation.format == "Sigma"


def test_incident_report_serialization_round_trip() -> None:
    report = _sample_report()
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

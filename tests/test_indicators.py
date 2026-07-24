"""Tests for the indicator processor and suspicious indicator model."""

from typing import Any

import pytest

from ovs_logs.core.analysis.indicators import (
    IndicatorProcessor,
    SuspiciousIndicator,
    extract_unique_ips,
)

INDICATORS_TOTAL_COUNT = 7
EXPECTED_EVENT_COUNT = 250


def _sample_results() -> dict[str, list[dict[str, Any]]]:
    return {
        "top_talkers": [
            {"source_ip": "1.2.3.4", "event_count": 250},
            {"source_ip": "5.6.7.8", "event_count": 125},
        ],
        "error_spikes": [{"source_ip": "1.2.3.4", "status_code": 404, "error_count": 120}],
        "event_distribution": [{"event_type": "GET", "event_count": 120}],
        "temporal_anomaly": [{"time_bucket": "2024-01-01 00:00:00", "event_count": 30}],
        "long_tail_analysis": [
            {
                "process_name": "powershell.exe",
                "destination_ip": "1.1.1.1",
                "connection_count": 1,
                "total_connections": 50,
            },
            {
                "process_name": "cmd.exe",
                "destination_ip": "2.2.2.2",
                "connection_count": 2,
                "total_connections": 50,
            },
        ],
    }


def test_default_thresholds_produce_expected_severity() -> None:
    processor = IndicatorProcessor()
    results = _sample_results()

    indicators = processor.process(results)

    assert len(indicators) == INDICATORS_TOTAL_COUNT

    top_high = next(i for i in indicators if i.type == "top_talkers" and i.evidence["source_ip"] == "1.2.3.4")
    assert top_high.severity == "High"
    assert "1.2.3.4" in top_high.description
    assert top_high.evidence["event_count"] == EXPECTED_EVENT_COUNT

    top_medium = next(i for i in indicators if i.type == "top_talkers" and i.evidence["source_ip"] == "5.6.7.8")
    assert top_medium.severity == "Medium"

    error = next(i for i in indicators if i.type == "error_spikes")
    assert error.severity == "High"
    assert "404" in error.description

    distribution = next(i for i in indicators if i.type == "event_distribution")
    assert distribution.severity == "Medium"
    assert "GET" in distribution.description

    temporal = next(i for i in indicators if i.type == "temporal_anomaly")
    assert temporal.severity == "Low"
    assert "Time bucket" in temporal.description

    # long_tail_analysis uses inverted severity: 1 = High, 2 = Medium (default=2)
    long_tail_high = next(
        i for i in indicators if i.type == "long_tail_analysis" and i.evidence["process_name"] == "powershell.exe"
    )
    assert long_tail_high.severity == "High"
    assert "powershell.exe" in long_tail_high.description
    assert "1.1.1.1" in long_tail_high.description
    assert "connection(s)" in long_tail_high.description

    long_tail_med = next(
        i for i in indicators if i.type == "long_tail_analysis" and i.evidence["process_name"] == "cmd.exe"
    )
    assert long_tail_med.severity == "Medium"
    assert "cmd.exe" in long_tail_med.description


def test_custom_thresholds_override_defaults() -> None:
    processor = IndicatorProcessor(
        thresholds={
            "top_talkers": 100,
            "error_spikes": 100,
        }
    )
    results = {
        "top_talkers": [{"source_ip": "1.2.3.4", "event_count": 150}],
        "error_spikes": [{"source_ip": "1.2.3.4", "status_code": 500, "error_count": 50}],
    }

    indicators = processor.process(results)

    top = indicators[0]
    assert top.severity == "Medium"  # 150 >= 100 but < 200

    error = indicators[1]
    assert error.severity == "Low"  # 50 < 100


def test_indicator_invalid_severity_rejected() -> None:
    with pytest.raises(ValueError, match="Severity must be"):
        SuspiciousIndicator(
            type="top_talkers",
            severity="Critical",
            description="Test",
            evidence={},
        )


def test_extract_unique_ips_skips_empty_and_non_string() -> None:
    indicators = [
        SuspiciousIndicator(type="top_talkers", severity="Low", description="d", evidence={"source_ip": "1.2.3.4"}),
        SuspiciousIndicator(type="top_talkers", severity="Low", description="d", evidence={"source_ip": ""}),
        SuspiciousIndicator(type="top_talkers", severity="Low", description="d", evidence={"source_ip": None}),
        SuspiciousIndicator(type="top_talkers", severity="Low", description="d", evidence={"source_ip": "1.2.3.4"}),
        SuspiciousIndicator(type="event_distribution", severity="Low", description="d", evidence={"event_type": "GET"}),
    ]

    assert extract_unique_ips(indicators) == ["1.2.3.4"]

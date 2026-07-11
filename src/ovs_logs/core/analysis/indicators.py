"""Suspicious indicator data model and result shaping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ovs_logs.config.settings import AnalysisThresholds, settings


def _thresholds_dict(source: AnalysisThresholds) -> dict[str, int]:
    """Build the threshold mapping from any settings object exposing the four fields."""
    return {
        "top_talkers": source.top_talkers,
        "error_spikes": source.error_spikes,
        "event_distribution": source.event_distribution,
        "temporal_anomaly": source.temporal_anomaly,
    }


def _default_thresholds() -> dict[str, int]:
    """Return the default indicator thresholds as a template-name mapping."""
    return _thresholds_dict(settings.thresholds)


@dataclass(frozen=True)
class SuspiciousIndicator:
    """A single suspicious indicator produced by the analysis pipeline."""

    type: str
    severity: str
    description: str
    evidence: dict[str, Any]

    def __post_init__(self) -> None:
        if self.severity not in {"Low", "Medium", "High"}:
            raise ValueError(f"Severity must be one of Low, Medium, or High; got {self.severity!r}")


class IndicatorProcessor:
    """Transforms raw analysis engine output into a flat list of indicators."""

    def __init__(
        self,
        thresholds: dict[str, int] | None = None,
        *,
        thresholds_settings: AnalysisThresholds | None = None,
    ) -> None:
        if thresholds_settings is not None:
            self.thresholds = _thresholds_dict(thresholds_settings)
        else:
            self.thresholds = _default_thresholds()
        if thresholds:
            self.thresholds.update(thresholds)

    def _severity(self, value: int, threshold: int) -> str:
        """Assign a severity level based on how much the value exceeds the threshold."""
        if threshold <= 0:
            return "Low"
        if value >= threshold * 2:
            return "High"
        if value >= threshold:
            return "Medium"
        return "Low"

    def _extract_value(self, indicator_type: str, evidence: dict[str, Any]) -> int:
        """Extract the numeric count used for severity scoring."""
        return int(evidence.get("event_count", 0) or evidence.get("error_count", 0) or 0)

    def _build_description(self, indicator_type: str, evidence: dict[str, Any]) -> str:
        """Generate a human-readable description for the indicator."""
        if indicator_type == "top_talkers":
            return f"IP {evidence['source_ip']} generated {evidence['event_count']} events"
        if indicator_type == "error_spikes":
            return f"IP {evidence['source_ip']} returned HTTP {evidence['status_code']} {evidence['error_count']} times"
        if indicator_type == "event_distribution":
            return f"Event type '{evidence['event_type']}' occurred {evidence['event_count']} times"
        if indicator_type == "temporal_anomaly":
            return f"Time bucket {evidence['time_bucket']} had {evidence['event_count']} events"
        return f"Indicator of type {indicator_type}: {evidence}"

    def process(self, results: dict[str, list[dict[str, Any]]]) -> list[SuspiciousIndicator]:
        """Convert raw analysis results into a flat list of suspicious indicators."""
        indicators: list[SuspiciousIndicator] = []

        for indicator_type, rows in results.items():
            threshold = self.thresholds.get(indicator_type, 0)
            for evidence in rows:
                value = self._extract_value(indicator_type, evidence)
                severity = self._severity(value, threshold)
                description = self._build_description(indicator_type, evidence)
                indicators.append(
                    SuspiciousIndicator(
                        type=indicator_type,
                        severity=severity,
                        description=description,
                        evidence=evidence,
                    )
                )

        return indicators


def extract_unique_ips(indicators: list[SuspiciousIndicator]) -> list[str]:
    """Collect unique ``source_ip`` values from indicator evidence.

    Useful for passing to a threat-intel client for bulk enrichment.
    """
    ips: set[str] = set()
    for indicator in indicators:
        ip = indicator.evidence.get("source_ip")
        if isinstance(ip, str) and ip:
            ips.add(ip)
    return sorted(ips)

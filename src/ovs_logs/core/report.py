"""Incident report schema for timeline, MITRE mapping, and mitigation output."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any

from ovs_logs.core.analysis.indicators import SuspiciousIndicator


@dataclass(frozen=True)
class TimelineEvent:
    """A single event in the incident timeline."""

    timestamp: str
    description: str
    source_ip: str | None = None
    event_type: str | None = None
    status_code: int | None = None
    raw_message: str | None = None


@dataclass(frozen=True)
class MitreMapping:
    """MITRE ATT&CK technique mapping for an observed behavior."""

    technique_id: str
    technique_name: str
    tactic: str
    description: str


@dataclass(frozen=True)
class MitigationArtifact:
    """A detections or mitigation rule in a specific format."""

    format: str
    title: str
    content: str


@dataclass(frozen=True)
class IncidentReport:
    """Full incident report produced by the LLM synthesis layer."""

    title: str
    summary: str
    severity: str
    timeline: list[TimelineEvent]
    mitre_mappings: list[MitreMapping]
    mitigation: MitigationArtifact
    indicators: list[SuspiciousIndicator]
    metadata: dict[str, Any]

    def __post_init__(self) -> None:
        if self.severity not in {"Low", "Medium", "High"}:
            raise ValueError(f"Incident severity must be Low, Medium, or High; got {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a JSON-friendly dictionary."""
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IncidentReport:
        """Reconstruct an incident report from a dictionary."""
        return cls(
            title=data["title"],
            summary=data["summary"],
            severity=data["severity"],
            timeline=[TimelineEvent(**item) for item in data.get("timeline", [])],
            mitre_mappings=[MitreMapping(**item) for item in data.get("mitre_mappings", [])],
            mitigation=MitigationArtifact(**data["mitigation"]),
            indicators=[SuspiciousIndicator(**item) for item in data.get("indicators", [])],
            metadata=data.get("metadata", {}),
        )

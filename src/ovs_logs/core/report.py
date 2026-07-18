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
        """Reconstruct an incident report from a dictionary.

        Tolerates the LLM emitting ``time`` instead of ``timestamp`` for
        timeline events, and varying MITRE mapping key names (``technique``
        aliased to ``technique_id``, ``name`` to ``technique_name``) or
        omitting ``tactic``/``description``, by normalizing and supplying
        sensible defaults before construction.
        """
        timeline = []
        for raw_item in data.get("timeline", []):
            item = raw_item
            if isinstance(item, dict):
                item = dict(item)
                if "time" in item and "timestamp" not in item:
                    item["timestamp"] = item.pop("time")
            timeline.append(TimelineEvent(**item))
        mitre_mappings = []
        for raw_item in data.get("mitre_mappings", []):
            item = raw_item if isinstance(raw_item, dict) else {}
            item = dict(item)
            if "technique" in item and "technique_id" not in item:
                item["technique_id"] = item.pop("technique")
            if "name" in item and "technique_name" not in item:
                item["technique_name"] = item.pop("name")
            item.setdefault("tactic", "")
            item.setdefault("description", item.get("technique_name", ""))
            mitre_mappings.append(MitreMapping(**item))
        indicators = []
        for raw_item in data.get("indicators", []):
            item = raw_item if isinstance(raw_item, dict) else {}
            item = dict(item)
            item.setdefault("description", "")
            indicators.append(SuspiciousIndicator(**item))
        return cls(
            title=data["title"],
            summary=data["summary"],
            severity=data["severity"],
            timeline=timeline,
            mitre_mappings=mitre_mappings,
            mitigation=MitigationArtifact(**data["mitigation"]),
            indicators=indicators,
            metadata=data.get("metadata", {}),
        )

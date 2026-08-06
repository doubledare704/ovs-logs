"""Incident report schema for timeline, MITRE mapping, and mitigation output."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any

from ovs_logs.core.analysis.indicators import SuspiciousIndicator


def _filter_known_fields(model: type[Any], data: dict[str, Any]) -> dict[str, Any]:
    """Return *data* restricted to the fields declared on the *model* dataclass.

    Local LLMs frequently emit keys outside the schema (e.g. ``event_count``
    on a timeline entry). Dropping unknown keys keeps parsing resilient
    instead of raising ``TypeError`` on dataclass construction.
    """
    known = {field.name for field in dataclasses.fields(model)}
    return {key: value for key, value in data.items() if key in known}


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
        aliased to ``technique_id``, ``name`` to ``technique_name``), by
        normalizing and supplying sensible defaults before construction.
        Required keys the model omitted (e.g. ``type`` on an indicator) get
        safe defaults instead of raising ``TypeError``, and keys not declared
        on a nested model (e.g. ``event_count`` on a timeline event) are
        dropped.
        """
        timeline = []
        for raw_item in data.get("timeline", []):
            if not isinstance(raw_item, dict):
                continue
            item = dict(raw_item)
            if "time" in item and "timestamp" not in item:
                item["timestamp"] = item.pop("time")
            item.setdefault("timestamp", "")
            item.setdefault("description", "")
            timeline.append(TimelineEvent(**_filter_known_fields(TimelineEvent, item)))
        mitre_mappings = []
        for raw_item in data.get("mitre_mappings", []):
            if not isinstance(raw_item, dict):
                continue
            item = dict(raw_item)
            if "technique" in item and "technique_id" not in item:
                item["technique_id"] = item.pop("technique")
            if "name" in item and "technique_name" not in item:
                item["technique_name"] = item.pop("name")
            item.setdefault("technique_id", "unknown")
            item.setdefault("technique_name", "")
            item.setdefault("tactic", "")
            item.setdefault("description", item.get("technique_name", ""))
            mitre_mappings.append(MitreMapping(**_filter_known_fields(MitreMapping, item)))
        indicators = []
        for raw_item in data.get("indicators", []):
            if not isinstance(raw_item, dict):
                continue
            item = dict(raw_item)
            item.setdefault("type", "unknown")
            item.setdefault("severity", "Medium")
            item.setdefault("description", "")
            item.setdefault("evidence", {})
            indicators.append(SuspiciousIndicator(**_filter_known_fields(SuspiciousIndicator, item)))
        mitigation_data = data.get("mitigation", {})
        mitigation_item = dict(mitigation_data) if isinstance(mitigation_data, dict) else {}
        mitigation_item.setdefault("format", "")
        mitigation_item.setdefault("title", "")
        mitigation_item.setdefault("content", "")
        mitigation = MitigationArtifact(**_filter_known_fields(MitigationArtifact, mitigation_item))
        return cls(
            title=data["title"],
            summary=data["summary"],
            severity=data["severity"],
            timeline=timeline,
            mitre_mappings=mitre_mappings,
            mitigation=mitigation,
            indicators=indicators,
            metadata=data.get("metadata", {}),
        )

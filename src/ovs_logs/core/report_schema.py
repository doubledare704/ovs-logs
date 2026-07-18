"""Pydantic response models for Ollama structured-output enforcement.

These mirror :class:`~ovs_logs.core.report.IncidentReport` and its sub-dataclasses so
that Ollama's ``format`` parameter can constrain the model to emit exactly the required
fields. Pydantic v2 emits ``"additionalProperties": false`` by default, which forbids the
model from returning unexpected keys.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

Severity = Literal["Low", "Medium", "High"]


class TimelineEventSchema(BaseModel):
    """A single event in the incident timeline."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    description: str
    source_ip: str | None = None
    event_type: str | None = None
    status_code: int | None = None
    raw_message: str | None = None


class MitreMappingSchema(BaseModel):
    """MITRE ATT&CK technique mapping for an observed behavior."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    tactic: str
    description: str


class MitigationSchema(BaseModel):
    """A detections or mitigation rule in a specific format."""

    model_config = ConfigDict(extra="forbid")

    format: str
    title: str
    content: str


class IndicatorSchema(BaseModel):
    """A suspicious indicator produced by the analysis pipeline."""

    model_config = ConfigDict(extra="forbid")

    type: str
    severity: Severity
    description: str
    evidence: dict[str, Any]


class IncidentReportSchema(BaseModel):
    """Full incident report produced by the LLM synthesis layer."""

    model_config = ConfigDict(extra="forbid")

    title: str
    summary: str
    severity: Severity
    timeline: list[TimelineEventSchema]
    mitre_mappings: list[MitreMappingSchema]
    mitigation: MitigationSchema
    indicators: list[IndicatorSchema]
    metadata: dict[str, Any]


REPORT_JSON_SCHEMA: dict[str, Any] = IncidentReportSchema.model_json_schema()

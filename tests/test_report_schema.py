"""Tests for the Pydantic-derived Ollama structured-output schema."""

from __future__ import annotations

from ovs_logs.core.report_schema import REPORT_JSON_SCHEMA


def _defs() -> dict:
    return REPORT_JSON_SCHEMA.get("$defs", {})


def test_schema_forbids_extra_root_properties() -> None:
    assert REPORT_JSON_SCHEMA.get("additionalProperties") is False


def test_schema_required_matches_report_fields() -> None:
    expected = {
        "title",
        "summary",
        "severity",
        "timeline",
        "mitre_mappings",
        "mitigation",
        "indicators",
        "metadata",
    }
    assert set(REPORT_JSON_SCHEMA["required"]) == expected


def test_nested_objects_forbid_extra_properties() -> None:
    for name in ("TimelineEventSchema", "MitreMappingSchema", "MitigationSchema", "IndicatorSchema"):
        assert _defs()[name].get("additionalProperties") is False


def test_mitre_mapping_required_fields() -> None:
    assert set(_defs()["MitreMappingSchema"]["required"]) == {
        "technique_id",
        "technique_name",
        "tactic",
        "description",
    }


def test_severity_is_enum() -> None:
    assert REPORT_JSON_SCHEMA["properties"]["severity"]["enum"] == ["Low", "Medium", "High"]

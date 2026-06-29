"""Tests for the anomaly detection analysis engine."""

from pathlib import Path

import pytest

from ovs_logs.core.analysis.engine import AnalysisEngine
from ovs_logs.core.database import Database
from ovs_logs.core.ingestion.adapters import load_csv
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.validation import validate_log_file


@pytest.fixture
def db():
    """In-memory DuckDB instance pre-populated with normalized events."""
    with Database(":memory:") as conn:
        yield conn


@pytest.fixture
def analysis_engine(db, tmp_path: Path):
    """Populate an `events` table and return an AnalysisEngine."""
    csv_file = tmp_path / "events.csv"
    csv_file.write_text(
        "timestamp,client_ip,status,method\n"
        "2024-01-01T00:00:00,1.2.3.4,200,GET\n"
        "2024-01-01T00:00:01,1.2.3.4,404,GET\n"
        "2024-01-01T00:00:02,1.2.3.4,500,POST\n"
        "2024-01-01T00:00:03,5.6.7.8,200,GET\n"
        "2024-01-01T00:07:00,5.6.7.8,200,GET\n"
    )

    log = validate_log_file(csv_file)
    load_result = load_csv(log, db, table_name="raw_events")
    NormalizationEngine().normalize_table(db, load_result)

    return AnalysisEngine()


def test_top_talkers(analysis_engine, db) -> None:
    results = analysis_engine.run_queries(
        db, thresholds={"top_talkers": {"min_events": 2, "limit": 10}}
    )

    top = results["top_talkers"]
    assert len(top) == 2
    assert top[0]["source_ip"] == "1.2.3.4"
    assert top[0]["event_count"] == 3
    assert top[1]["source_ip"] == "5.6.7.8"
    assert top[1]["event_count"] == 2


def test_error_spikes(analysis_engine, db) -> None:
    results = analysis_engine.run_queries(
        db, thresholds={"error_spikes": {"min_errors": 1, "limit": 10}}
    )

    errors = results["error_spikes"]
    assert len(errors) == 2
    ips = {row["source_ip"] for row in errors}
    assert "1.2.3.4" in ips
    assert any(row["status_code"] == 404 for row in errors)
    assert any(row["status_code"] == 500 for row in errors)


def test_event_distribution(analysis_engine, db) -> None:
    results = analysis_engine.run_queries(db)

    distribution = results["event_distribution"]
    types = {row["event_type"]: row["event_count"] for row in distribution}
    assert types["GET"] == 4
    assert types["POST"] == 1


def test_temporal_anomaly(analysis_engine, db) -> None:
    results = analysis_engine.run_queries(
        db, thresholds={"temporal_anomaly": {"min_events": 1, "limit": 10}}
    )

    buckets = results["temporal_anomaly"]
    assert len(buckets) == 2
    assert buckets[0]["event_count"] == 4
    assert buckets[1]["event_count"] == 1

"""Tests for the anomaly detection analysis engine."""

from pathlib import Path

import pytest

from ovs_logs.core.analysis.engine import AnalysisEngine
from ovs_logs.core.ingestion.adapters import load_csv
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.validation import validate_log_file

TOP_TALKERS_COUNT = 2
TOP_TALKER_1_COUNT = 3
TOP_TALKER_2_COUNT = 2
ERROR_SPIKES_COUNT = 2
ERROR_STATUS_404 = 404
ERROR_STATUS_500 = 500
GET_COUNT = 4
POST_COUNT = 1
TEMPORAL_BUCKETS_COUNT = 2
TEMPORAL_BUCKET_0_COUNT = 4
TEMPORAL_BUCKET_1_COUNT = 1


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
    results = analysis_engine.run_queries(db, thresholds={"top_talkers": {"min_events": 2, "limit": 10}})

    top = results["top_talkers"]
    assert len(top) == TOP_TALKERS_COUNT
    assert top[0]["source_ip"] == "1.2.3.4"
    assert top[0]["event_count"] == TOP_TALKER_1_COUNT
    assert top[1]["source_ip"] == "5.6.7.8"
    assert top[1]["event_count"] == TOP_TALKER_2_COUNT


def test_error_spikes(analysis_engine, db) -> None:
    results = analysis_engine.run_queries(db, thresholds={"error_spikes": {"min_errors": 1, "limit": 10}})

    errors = results["error_spikes"]
    assert len(errors) == ERROR_SPIKES_COUNT
    ips = {row["source_ip"] for row in errors}
    assert "1.2.3.4" in ips
    assert any(row["status_code"] == ERROR_STATUS_404 for row in errors)
    assert any(row["status_code"] == ERROR_STATUS_500 for row in errors)


def test_event_distribution(analysis_engine, db) -> None:
    results = analysis_engine.run_queries(db)

    distribution = results["event_distribution"]
    types = {row["event_type"]: row["event_count"] for row in distribution}
    assert types["GET"] == GET_COUNT
    assert types["POST"] == POST_COUNT


def test_temporal_anomaly(analysis_engine, db) -> None:
    results = analysis_engine.run_queries(db, thresholds={"temporal_anomaly": {"min_events": 1, "limit": 10}})

    buckets = results["temporal_anomaly"]
    assert len(buckets) == TEMPORAL_BUCKETS_COUNT
    assert buckets[0]["event_count"] == TEMPORAL_BUCKET_0_COUNT
    assert buckets[1]["event_count"] == TEMPORAL_BUCKET_1_COUNT


def test_error_spikes_raw_varchar_status_code(db) -> None:
    db.execute(
        "CREATE TABLE raw_logs AS SELECT "
        "'10.0.0.1' AS source_ip, '404' AS status_code, 'GET' AS event_type, 'line' AS raw_message "
        "UNION ALL SELECT '10.0.0.2', '500', 'POST', 'line' "
        "UNION ALL SELECT '10.0.0.3', '', 'GET', 'line'"
    )

    results = AnalysisEngine().run_queries(
        db, table_name="raw_logs", thresholds={"error_spikes": {"min_errors": 1, "limit": 10}}
    )

    errors = results["error_spikes"]
    assert len(errors) == ERROR_SPIKES_COUNT
    assert any(row["status_code"] == ERROR_STATUS_404 for row in errors)
    assert any(row["status_code"] == ERROR_STATUS_500 for row in errors)

"""Tests for the normalization engine."""

from collections.abc import Sequence
from pathlib import Path

import pytest

from ovs_logs.core.database import Database
from ovs_logs.core.ingestion.adapters import load_csv, load_json, load_text_log
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.validation import validate_log_file

NORMALIZED_CSV_ROW_COUNT = 2
NORMALIZED_LOG_ROW_COUNT = 2


@pytest.fixture
def db():
    """In-memory DuckDB instance for normalization tests."""
    with Database(":memory:") as conn:
        yield conn


def _schema_types(schema: Sequence[tuple[str, str]]) -> dict[str, str]:
    return {name.lower(): dtype for name, dtype in schema}


def test_normalize_csv(db, tmp_path: Path) -> None:
    file = tmp_path / "web.csv"
    file.write_text(
        "timestamp,client_ip,status,method\n2024-01-01T00:00:00,1.2.3.4,200,GET\n2024-01-01T00:01:00,5.6.7.8,404,POST\n"
    )

    log = validate_log_file(file)
    load_result = load_csv(log, db, table_name="raw_web")
    result = NormalizationEngine().normalize_table(db, load_result)

    assert result.table_name == "events"
    assert result.row_count == NORMALIZED_CSV_ROW_COUNT
    assert result.mapping["source_ip"] == "client_ip"
    assert result.mapping["event_type"] == "method"
    assert result.mapping["status_code"] == "status"
    assert result.mapping["event_timestamp"] == "timestamp"
    assert result.mapping["raw_message"] is None

    types = _schema_types(result.schema)
    assert "timestamp" in types["event_timestamp"].lower()
    assert "integer" in types["status_code"].lower()

    rows = db.execute("SELECT source_ip, status_code, event_type FROM events ORDER BY event_timestamp").fetchall()
    assert rows[0] == ("1.2.3.4", 200, "GET")
    assert rows[1] == ("5.6.7.8", 404, "POST")


def test_normalize_json(db, tmp_path: Path) -> None:
    file = tmp_path / "events.json"
    file.write_text(
        '[{"time":"2024-02-01T12:00:00","remote_addr":"9.8.7.6",'
        '"action":"login","response_code":201,"message":"User logged in"}]'
    )

    log = validate_log_file(file)
    load_result = load_json(log, db, table_name="raw_events")
    result = NormalizationEngine().normalize_table(db, load_result)

    assert result.row_count == 1
    assert result.mapping["source_ip"] == "remote_addr"
    assert result.mapping["event_type"] == "action"
    assert result.mapping["status_code"] == "response_code"
    assert result.mapping["event_timestamp"] == "time"
    assert result.mapping["raw_message"] == "message"

    rows = db.execute("SELECT source_ip, status_code, event_type, raw_message FROM events").fetchall()
    assert rows[0] == ("9.8.7.6", 201, "login", "User logged in")


def test_normalize_text_log(db, tmp_path: Path) -> None:
    file = tmp_path / "app.log"
    file.write_text("line one\nline two\n")

    log = validate_log_file(file)
    load_result = load_text_log(log, db, table_name="raw_app")
    result = NormalizationEngine().normalize_table(db, load_result)

    assert result.row_count == NORMALIZED_LOG_ROW_COUNT
    assert result.mapping["raw_message"] == "line"
    assert result.mapping["source_ip"] is None
    assert result.mapping["event_timestamp"] is None

    rows = db.execute("SELECT raw_message FROM events ORDER BY raw_message").fetchall()
    assert rows == [("line one",), ("line two",)]


def test_normalize_unmatched_columns(db, tmp_path: Path) -> None:
    file = tmp_path / "other.csv"
    file.write_text("foo,bar\n1,2\n")

    log = validate_log_file(file)
    load_result = load_csv(log, db, table_name="raw_other")
    result = NormalizationEngine().normalize_table(db, load_result)

    assert result.row_count == 1
    for target in ["event_timestamp", "source_ip", "event_type", "status_code", "raw_message"]:
        assert result.mapping[target] is None

    rows = db.execute("SELECT * FROM events").fetchall()
    assert rows[0] == (None, None, None, None, None)

"""Tests for the normalization engine."""

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from ovs_logs.core.ingestion.adapters import load_csv, load_json, load_text_log
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.text_parsing import parse_text_log
from ovs_logs.core.validation import validate_log_file

NORMALIZED_CSV_ROW_COUNT = 2
NORMALIZED_LOG_ROW_COUNT = 2


def _schema_types(schema: Sequence[tuple[str, str]]) -> dict[str, str]:
    """Extract lowercased column names to dtype mapping from a DuckDB DESCRIBE result."""
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


def test_normalize_web_apache_timestamp_to_utc(db, tmp_path: Path) -> None:
    """Apache/nginx combined timestamps must populate ``event_timestamp`` as UTC."""
    file = tmp_path / "access.log"
    file.write_text(
        '10.0.0.1 - - [14/Nov/2023:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024\n'
        '10.0.0.2 - - [14/Nov/2023:14:00:00 +0200] "POST /api/login HTTP/1.1" 401 512\n'
    )

    log = validate_log_file(file)
    load_result = parse_text_log(log, db, table_name="raw_web")
    result = NormalizationEngine().normalize_table(db, load_result)

    assert result.mapping["event_timestamp"] == "event_timestamp"

    rows = db.execute("SELECT event_timestamp, source_ip FROM events").fetchall()
    # Both timestamps normalize to the same UTC instant (12:00:00 +0000 and 14:00:00 +0200)
    assert {row[0] for row in rows} == {datetime(2023, 11, 14, 12, 0, 0)}
    assert {row[1] for row in rows} == {"10.0.0.1", "10.0.0.2"}

    # Raw timestamp column is preserved (non-destructive)
    raw = db.execute('SELECT "event_timestamp" FROM "raw_web" ORDER BY "event_timestamp"').fetchall()
    assert raw[0][0] == "14/Nov/2023:12:00:00 +0000"
    assert raw[1][0] == "14/Nov/2023:14:00:00 +0200"


def test_normalize_json_epoch_timestamp(db, tmp_path: Path) -> None:
    """Numeric epoch timestamps must populate ``event_timestamp``."""
    file = tmp_path / "events.json"
    file.write_text('[{"ts": 1431433200, "src_ip": "1.2.3.4", "status": 200}]')

    log = validate_log_file(file)
    load_result = load_json(log, db, table_name="raw_events")
    result = NormalizationEngine().normalize_table(db, load_result)

    assert result.mapping["event_timestamp"] == "ts"
    rows = db.execute("SELECT event_timestamp, source_ip FROM events").fetchall()
    assert rows[0] == (datetime(2015, 5, 12, 15, 20, 0), "1.2.3.4")


def test_normalize_batch_appends_without_data_loss(db, tmp_path: Path) -> None:
    """A second batch must append to ``events`` rather than overwrite it."""
    first = tmp_path / "first.csv"
    first.write_text("timestamp,client_ip,status,method\n2024-01-01T00:00:00,1.2.3.4,200,GET\n")
    second = tmp_path / "second.csv"
    second.write_text("timestamp,client_ip,status,method\n2024-01-02T00:00:00,5.6.7.8,404,POST\n")

    engine = NormalizationEngine()

    load_first = load_csv(validate_log_file(first), db, table_name="raw_first")
    count_after_first = engine.normalize_batch(db, [("raw_first", [n for n, _ in load_first.schema])])
    assert count_after_first == 1

    load_second = load_csv(validate_log_file(second), db, table_name="raw_second")
    count_after_second = engine.normalize_batch(db, [("raw_second", [n for n, _ in load_second.schema])])

    assert count_after_second == 2  # first batch rows retained
    ips = {row[0] for row in db.execute("SELECT source_ip FROM events").fetchall()}
    assert ips == {"1.2.3.4", "5.6.7.8"}


def test_normalize_batch_empty_returns_zero(db) -> None:
    assert NormalizationEngine().normalize_batch(db, []) == 0


def test_normalize_batch_is_idempotent_per_source(db, tmp_path: Path) -> None:
    """Re-normalizing the same raw table must not duplicate rows in ``events``."""
    file = tmp_path / "same.csv"
    file.write_text("timestamp,client_ip,status,method\n2024-01-01T00:00:00,1.2.3.4,200,GET\n")

    engine = NormalizationEngine()
    load = load_csv(validate_log_file(file), db, table_name="raw_same")
    columns = [n for n, _ in load.schema]

    first = engine.normalize_batch(db, [("raw_same", columns)])
    second = engine.normalize_batch(db, [("raw_same", columns)])

    assert first == 1
    assert second == 1  # unchanged: source already merged, no duplicate appended

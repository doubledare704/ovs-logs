"""Tests for the DuckDB ingestion adapters."""

import tempfile
from pathlib import Path

import pytest

from ovs_logs.core.ingestion import adapters
from ovs_logs.core.ingestion.adapters import (
    EVTX_CSV_FIELDNAMES,
    LoadResult,
    load_csv,
    load_evtx,
    load_json,
    load_text_log,
)
from ovs_logs.core.validation import validate_log_file

from .conftest import schema_columns

EXPECTED_CSV_ROW_COUNT = 2
EXPECTED_JSON_ROW_COUNT = 2
EXPECTED_LOG_ROW_COUNT = 3
EVTX_RECORD_ID = 12345


def test_load_csv(db, tmp_path: Path) -> None:
    file = tmp_path / "sample.csv"
    file.write_text("timestamp,client_ip,status\n2024-01-01T00:00:00,1.2.3.4,200\n2024-01-01T00:01:00,5.6.7.8,404\n")

    log = validate_log_file(file)
    result = load_csv(log, db, table_name="test_csv")

    assert isinstance(result, LoadResult)
    assert result.table_name == "test_csv"
    assert result.row_count == EXPECTED_CSV_ROW_COUNT
    assert {"timestamp", "client_ip", "status"}.issubset(schema_columns(result.schema))


def test_load_json(db, tmp_path: Path) -> None:
    file = tmp_path / "sample.json"
    file.write_text('[{"id":1,"event":"login","ip":"1.2.3.4"},{"id":2,"event":"logout","ip":"5.6.7.8"}]')

    log = validate_log_file(file)
    result = load_json(log, db, table_name="test_json")

    assert result.table_name == "test_json"
    assert result.row_count == EXPECTED_JSON_ROW_COUNT
    assert {"id", "event", "ip"}.issubset(schema_columns(result.schema))


def test_load_text_log(db, tmp_path: Path) -> None:
    file = tmp_path / "sample.log"
    file.write_text("line one\nline two\nline three\n")

    log = validate_log_file(file)
    result = load_text_log(log, db, table_name="test_log")

    assert result.table_name == "test_log"
    assert result.row_count == EXPECTED_LOG_ROW_COUNT
    assert "line" in schema_columns(result.schema)


def test_load_evtx_converts_to_csv(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = tmp_path / "sample.evtx"
    file.write_bytes(b"EVT\x00...")

    class FakeParser:
        def __init__(self, path: str) -> None:
            self.path = path

        def records_json(self):
            return [
                {
                    "event_record_id": EVTX_RECORD_ID,
                    "timestamp": "2024-01-01T00:00:00Z",
                    "data": {
                        "Event": {
                            "System": {
                                "Provider": {
                                    "#attributes": {
                                        "Name": "Microsoft-Windows-Security-Auditing",
                                        "Guid": "{guid}",
                                    }
                                },
                                "EventID": {"#text": 4624, "#attributes": {"Qualifiers": "0"}},
                                "Version": 2,
                                "Level": 0,
                                "Task": 12544,
                                "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                                "Channel": "Security",
                                "Computer": "HOST.example.com",
                            },
                            "EventData": {
                                "Data": [
                                    {"#attributes": {"Name": "SubjectUserName"}, "#text": "alice"},
                                    {"#attributes": {"Name": "IpAddress"}, "#text": "1.2.3.4"},
                                    {"#attributes": {"Name": "StatusCode"}, "#text": "0"},
                                ]
                            },
                        }
                    },
                }
            ]

    monkeypatch.setattr(adapters, "PyEvtxParser", FakeParser)

    log = validate_log_file(file)
    assert log.format == "evtx"
    assert log.needs_conversion

    result = load_evtx(log, db, table_name="test_evtx")

    assert result.table_name == "test_evtx"
    assert result.row_count == 1
    columns = schema_columns(result.schema)
    expected_columns = set(EVTX_CSV_FIELDNAMES)
    assert expected_columns.issubset(columns)

    row = db.execute('SELECT * FROM "test_evtx"').fetchone()
    col_index = {name.lower(): i for i, (name, _) in enumerate(result.schema)}
    assert row[col_index["record_id"]] == EVTX_RECORD_ID
    assert row[col_index["timestamp"]] is not None
    assert str(row[col_index["event"]]) == "4624"
    assert row[col_index["source_ip"]] == "1.2.3.4"
    assert str(row[col_index["status_code"]]) == "0"
    assert row[col_index["provider"]] == "Microsoft-Windows-Security-Auditing"
    assert row[col_index["channel"]] == "Security"
    assert row[col_index["computer"]] == "HOST.example.com"
    assert str(row[col_index["level"]]) == "0"
    assert str(row[col_index["task"]]) == "12544"
    assert "System_TimeCreated_SystemTime" in row[col_index["message"]]


def test_load_evtx_raises_for_unparseable_file(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = tmp_path / "sample.evtx"
    file.write_bytes(b"EVT\x00...")

    class FailingParser:
        def __init__(self, path: str) -> None:
            self.path = path

        def records_json(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(adapters, "PyEvtxParser", FailingParser)

    log = validate_log_file(file)

    with pytest.raises(RuntimeError, match="Unable to parse EVTX"):
        load_evtx(log, db, table_name="test_evtx")


def test_extract_evtx_fields_preserves_list_values_as_json_arrays() -> None:
    row = adapters._extract_evtx_fields(
        {"EventData": {"Tags": ["alpha", "beta"]}},
        {"identifier": "1"},
    )

    assert '"EventData_Tags": ["alpha", "beta"]' in row["message"]


def test_load_evtx_cleans_up_temporary_csv_on_parser_error(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = tmp_path / "sample.evtx"
    file.write_bytes(b"EVT\x00...")
    created_paths: list[str] = []

    class FailingParser:
        def __init__(self, path: str) -> None:
            self.path = path

        def records_json(self):
            yield {
                "event_record_id": 1,
                "data": {
                    "Event": {
                        "System": {
                            "EventID": {"#text": 4624, "#attributes": {"Qualifiers": "0"}},
                            "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                        },
                        "EventData": {"Data": [{"#attributes": {"Name": "IpAddress"}, "#text": "1.2.3.4"}]},
                    }
                },
            }
            raise RuntimeError("boom")

    original_named_temporary_file = tempfile.NamedTemporaryFile

    def tracking_named_temporary_file(*args, **kwargs):
        handle = original_named_temporary_file(*args, **kwargs)
        created_paths.append(handle.name)
        return handle

    monkeypatch.setattr(adapters, "PyEvtxParser", FailingParser)
    monkeypatch.setattr(adapters.tempfile, "NamedTemporaryFile", tracking_named_temporary_file)

    log = validate_log_file(file)

    with pytest.raises(RuntimeError, match="Unable to parse EVTX"):
        load_evtx(log, db, table_name="test_evtx")

    assert created_paths
    assert not any(Path(path).exists() for path in created_paths)

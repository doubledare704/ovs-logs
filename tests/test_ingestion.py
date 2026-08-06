"""Tests for the DuckDB ingestion adapters."""

import json
import subprocess
from pathlib import Path
from subprocess import CalledProcessError, TimeoutExpired
from typing import Any, Never

import duckdb
import pytest

from ovs_logs.config.settings import EVTXToolSettings, Settings
from ovs_logs.core.errors import BinaryNotFoundError, IngestionError
from ovs_logs.core.ingestion import adapters
from ovs_logs.core.ingestion.adapters import (
    _CORRELATION_VIEW_NAME,
    EVTX_CSV_FIELDNAMES,
    EVTX_TOOL_ADAPTERS,
    EVTX_TOOL_CHOICES,
    HayabusaEngine,
    HybridIngestionPipeline,
    HybridIngestionResult,
    IngestionResult,
    PyEvtxEngine,
    ingest_evtx_hybrid,
    is_hayabusa_available,
    load_csv,
    load_evtx,
    load_evtx_via_hayabusa,
    load_evtx_via_hayabusa_json,
    load_json,
    load_text_log,
)
from ovs_logs.core.validation import validate_log_file

from .conftest import schema_columns

EXPECTED_CSV_ROW_COUNT = 2
EXPECTED_JSON_ROW_COUNT = 2
EXPECTED_LOG_ROW_COUNT = 3
EVTX_RECORD_ID = 12345


def test_evtx_tool_choices_match_adapter_mapping() -> None:
    """EVTX_TOOL_CHOICES must mirror EVTX_TOOL_ADAPTERS keys (single source of truth)."""
    assert tuple(EVTX_TOOL_ADAPTERS) == EVTX_TOOL_CHOICES
    assert set(EVTX_TOOL_ADAPTERS) == {"default", "hayabusa", "hayabusa-json", "hybrid"}
    assert EVTX_TOOL_ADAPTERS["default"] is load_evtx
    assert EVTX_TOOL_ADAPTERS["hybrid"] is ingest_evtx_hybrid


def test_load_csv(db, tmp_path: Path) -> None:
    file = tmp_path / "sample.csv"
    file.write_text("timestamp,client_ip,status\n2024-01-01T00:00:00,1.2.3.4,200\n2024-01-01T00:01:00,5.6.7.8,404\n")

    log = validate_log_file(file)
    result = load_csv(log, db, table_name="test_csv")

    assert isinstance(result, IngestionResult)
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
            data_json_str = json.dumps(
                {
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
                }
            )
            return [
                {
                    "event_record_id": EVTX_RECORD_ID,
                    "timestamp": "2024-01-01T00:00:00Z",
                    "data": data_json_str,
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

    message = row["message"]
    assert isinstance(message, str)
    assert '"EventData_Tags": ["alpha", "beta"]' in message


def test_load_evtx_cleans_up_temporary_csv_on_parser_error(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = tmp_path / "sample.evtx"
    file.write_bytes(b"EVT\x00...")

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

    monkeypatch.setattr(adapters, "PyEvtxParser", FailingParser)

    log = validate_log_file(file)

    with pytest.raises(RuntimeError, match="Unable to parse EVTX"):
        load_evtx(log, db, table_name="test_evtx")


def _make_evtx_file(tmp_path: Path, name: str = "sample.evtx") -> Path:
    """Create a dummy EVTX file for adapter tests."""
    file = tmp_path / name
    file.write_bytes(b"EVT\x00...")
    return file


def _custom_settings(
    hayabusa_path: str = "hayabusa",
    timeout_seconds: int = 300,
) -> Settings:
    """Return a Settings with custom EVTX tool paths."""
    return Settings(
        evtx_tools=EVTXToolSettings(
            hayabusa_path=hayabusa_path,
            timeout_seconds=timeout_seconds,
        ),
    )


def test_load_evtx_via_hayabusa(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="fake-hayabusa"),
    )

    output_csv = "timestamp,computer,event_id,channel\n2024-01-01T00:00:00,HOST,4624,Security\n"

    def fake_run(cmd, *args, **kwargs):
        output_arg = None
        for i, part in enumerate(cmd):
            if part == "-o" and i + 1 < len(cmd):
                output_arg = cmd[i + 1]
                break
        if output_arg:
            Path(output_arg).write_text(output_csv, encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = load_evtx_via_hayabusa(log, db, table_name="test_hayabusa")

    assert result.table_name == "test_hayabusa"
    assert result.row_count == 1
    columns = schema_columns(result.schema)
    assert "timestamp" in columns
    assert "computer" in columns


def test_load_evtx_via_hayabusa_binary_not_found(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="nonexistent-hayabusa"),
    )

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("No such file")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(BinaryNotFoundError, match="hayabusa binary not found"):
        load_evtx_via_hayabusa(log, db)


def test_load_evtx_via_hayabusa_process_failure(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="fake-hayabusa"),
    )

    def fake_run(*args, **kwargs):
        raise CalledProcessError(returncode=1, cmd=["hayabusa"], stderr="parse error")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="hayabusa failed"):
        load_evtx_via_hayabusa(log, db)


def test_load_evtx_via_hayabusa_timeout(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="fake-hayabusa", timeout_seconds=10),
    )

    def fake_run(*args, **kwargs):
        raise TimeoutExpired(cmd=["hayabusa"], timeout=10)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="hayabusa timed out"):
        load_evtx_via_hayabusa(log, db)


def test_load_evtx_via_hayabusa_missing_output(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="fake-hayabusa"),
    )

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=["hayabusa"], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="hayabusa produced no output"):
        load_evtx_via_hayabusa(log, db)


def test_load_evtx_via_hayabusa_permission_error(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="non-executable-hayabusa"),
    )

    def fake_run(*args, **kwargs):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="hayabusa is not executable"):
        load_evtx_via_hayabusa(log, db)


def test_load_evtx_via_hayabusa_json(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)
    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="fake-hayabusa"),
    )

    output_json = '{"timestamp":"2024-01-01T00:00:00","computer":"HOST","event_id":"4624","channel":"Security"}\n'

    def fake_run(cmd: list[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        output_arg = None
        for i, part in enumerate(cmd):
            if part == "-o" and i + 1 < len(cmd):
                output_arg = cmd[i + 1]
                break
        if output_arg:
            Path(output_arg).write_text(output_json, encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = load_evtx_via_hayabusa_json(log, db, table_name="test_hayabusa_json")

    assert result.table_name == "test_hayabusa_json"
    assert result.row_count == 1
    columns = schema_columns(result.schema)
    assert "timestamp" in columns
    assert "computer" in columns


def test_load_evtx_via_hayabusa_json_binary_not_found(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)
    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="nonexistent-hayabusa"),
    )

    def fake_run(*args: Any, **kwargs: Any) -> Never:
        raise FileNotFoundError("No such file")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(BinaryNotFoundError, match="hayabusa binary not found"):
        load_evtx_via_hayabusa_json(log, db)


def test_load_evtx_via_hayabusa_json_process_failure(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)
    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="fake-hayabusa"),
    )

    def fake_run(*args: Any, **kwargs: Any) -> Never:
        raise CalledProcessError(returncode=1, cmd=["hayabusa"], stderr="parse error")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="hayabusa failed"):
        load_evtx_via_hayabusa_json(log, db)


def test_load_evtx_via_hayabusa_json_timeout(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)
    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="fake-hayabusa", timeout_seconds=10),
    )

    def fake_run(*args: Any, **kwargs: Any) -> Never:
        raise TimeoutExpired(cmd=["hayabusa"], timeout=10)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="hayabusa timed out"):
        load_evtx_via_hayabusa_json(log, db)


def test_load_evtx_via_hayabusa_json_missing_output(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)
    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path="fake-hayabusa"),
    )

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=["hayabusa"], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="hayabusa produced no output"):
        load_evtx_via_hayabusa_json(log, db)


# ---------------------------------------------------------------------------
# Hybrid pipeline tests
# ---------------------------------------------------------------------------


def _make_fake_parser_class():
    """Return a FakeParser class for monkeypatching PyEvtxParser."""

    class FakeParser:
        def __init__(self, path: str) -> None:
            self.path = path

        def records_json(self):
            data_json_str = json.dumps(
                {
                    "Event": {
                        "System": {
                            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                            "EventID": {"#text": 4624, "#attributes": {"Qualifiers": "0"}},
                            "Level": 0,
                            "Task": 12544,
                            "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                            "Channel": "Security",
                            "Computer": "HOST.example.com",
                        },
                        "EventData": {
                            "Data": [
                                {"#attributes": {"Name": "IpAddress"}, "#text": "1.2.3.4"},
                                {"#attributes": {"Name": "StatusCode"}, "#text": "0"},
                            ]
                        },
                    }
                }
            )
            return [
                {
                    "event_record_id": EVTX_RECORD_ID,
                    "timestamp": "2024-01-01T00:00:00Z",
                    "data": data_json_str,
                }
            ]

    return FakeParser


def test_pyevtx_engine_is_always_available() -> None:
    assert PyEvtxEngine().is_available() is True


def test_pyevtx_engine_name() -> None:
    assert PyEvtxEngine().name == "raw"


def test_pyevtx_engine_ingest(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapters, "PyEvtxParser", _make_fake_parser_class())
    log = validate_log_file(_make_evtx_file(tmp_path))

    engine = PyEvtxEngine()
    output = tmp_path / "raw.csv"
    engine.ingest(log, output)

    assert output.exists()
    assert output.stat().st_size > 0


def test_hayabusa_engine_unavailable_when_binary_missing(tmp_path: Path) -> None:
    settings = _custom_settings(hayabusa_path=str(tmp_path / "nonexistent"))
    assert HayabusaEngine(settings.evtx_tools).is_available() is False


def test_hayabusa_engine_available_when_binary_exists(tmp_path: Path) -> None:
    binary = tmp_path / "hayabusa"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    settings = _custom_settings(hayabusa_path=str(binary))
    assert HayabusaEngine(settings.evtx_tools).is_available() is True


def test_hayabusa_engine_name() -> None:
    assert HayabusaEngine().name == "alerts"


def test_is_hayabusa_available_returns_false_for_missing_path(tmp_path: Path) -> None:
    settings = _custom_settings(hayabusa_path=str(tmp_path / "nope"))
    assert is_hayabusa_available(settings.evtx_tools) is False


def test_is_hayabusa_available_returns_true_for_existing_binary(tmp_path: Path) -> None:
    binary = tmp_path / "hayabusa"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    settings = _custom_settings(hayabusa_path=str(binary))
    assert is_hayabusa_available(settings.evtx_tools) is True


def test_hybrid_both_engines(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapters, "PyEvtxParser", _make_fake_parser_class())

    hayabusa_json = '{"Timestamp":"2024-01-01T00:00:00Z","Computer":"HOST","Channel":"Security","RecordID":12345}\n'

    def fake_run(cmd: list[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        for i, part in enumerate(cmd):
            if part == "-o" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(hayabusa_json, encoding="utf-8")
                break
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    binary = tmp_path / "hayabusa"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path=str(binary)),
    )

    log = validate_log_file(_make_evtx_file(tmp_path))
    result = ingest_evtx_hybrid(log, db, table_name="hybrid_test")

    assert isinstance(result, HybridIngestionResult)
    assert result.table_name == "hybrid_test_raw"
    assert result.row_count == 1
    assert result.hayabusa_executed is True
    assert result.hayabusa_result is not None
    assert result.alerts_table_name == "hybrid_test_alerts"

    raw_cols = schema_columns(result.schema)
    assert {"record_id", "timestamp", "event", "channel", "computer"}.issubset(raw_cols)

    alert_cols = schema_columns(result.hayabusa_result.schema)
    assert "Timestamp" in alert_cols or "timestamp" in alert_cols

    view_check = db.execute(f'SELECT 1 FROM "{_CORRELATION_VIEW_NAME}" LIMIT 1').fetchone()
    assert view_check is not None


def test_hybrid_hayabusa_unavailable_graceful_fallback(
    db,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapters, "PyEvtxParser", _make_fake_parser_class())
    settings = _custom_settings(hayabusa_path=str(tmp_path / "nonexistent"))
    monkeypatch.setattr("ovs_logs.core.ingestion.adapters.settings", settings)

    log = validate_log_file(_make_evtx_file(tmp_path))
    result = ingest_evtx_hybrid(log, db, table_name="hybrid_fallback")

    assert isinstance(result, HybridIngestionResult)
    assert result.table_name == "hybrid_fallback_raw"
    assert result.row_count == 1
    assert result.hayabusa_executed is False
    assert result.hayabusa_result is None
    assert result.alerts_table_name is None

    with pytest.raises(duckdb.Error):
        db.execute(f'SELECT 1 FROM "{_CORRELATION_VIEW_NAME}" LIMIT 1')


def test_hybrid_hayabusa_fails_still_returns_raw(
    db,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapters, "PyEvtxParser", _make_fake_parser_class())

    def fake_run(*args: Any, **kwargs: Any) -> None:
        raise CalledProcessError(returncode=1, cmd=["hayabusa"], stderr="error")

    monkeypatch.setattr(subprocess, "run", fake_run)

    binary = tmp_path / "hayabusa"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path=str(binary)),
    )

    log = validate_log_file(_make_evtx_file(tmp_path))
    result = ingest_evtx_hybrid(log, db, table_name="hybrid_fail")

    assert isinstance(result, HybridIngestionResult)
    assert result.table_name == "hybrid_fail_raw"
    assert result.row_count == 1
    assert result.hayabusa_executed is False
    assert result.hayabusa_result is None


def test_hybrid_hayabusa_empty_output_skipped(
    db,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapters, "PyEvtxParser", _make_fake_parser_class())

    def fake_run(cmd: list[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        for i, part in enumerate(cmd):
            if part == "-o" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text("", encoding="utf-8")
                break
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    binary = tmp_path / "hayabusa"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path=str(binary)),
    )

    log = validate_log_file(_make_evtx_file(tmp_path))
    result = ingest_evtx_hybrid(log, db, table_name="hybrid_empty")

    assert result.hayabusa_executed is False
    assert result.alerts_table_name is None


def test_hybrid_result_inherits_ingestion_result() -> None:
    assert issubclass(HybridIngestionResult, IngestionResult)


def test_hybrid_custom_engines_pipeline(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapters, "PyEvtxParser", _make_fake_parser_class())

    class DummyEngine:
        @property
        def name(self) -> str:
            return "alerts"

        def is_available(self) -> bool:
            return True

        def ingest(self, log_file, output_path: Path) -> None:
            output_path.write_text('{"col":"val"}\n', encoding="utf-8")

    log = validate_log_file(_make_evtx_file(tmp_path))
    pipeline = HybridIngestionPipeline(
        engines=[PyEvtxEngine(), DummyEngine()],
        connection=db,
    )
    result = pipeline.execute(log, "custom_engines")

    assert isinstance(result, HybridIngestionResult)
    assert result.row_count == 1
    assert result.hayabusa_executed is True


def test_correlation_view_joins_correctly(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapters, "PyEvtxParser", _make_fake_parser_class())

    hayabusa_json = json.dumps(
        {
            "Timestamp": "2024-01-01T00:00:00Z",
            "Computer": "HOST.example.com",
            "Channel": "Security",
            "RecordID": EVTX_RECORD_ID,
            "AlertName": "Test Detection",
        }
    )

    def fake_run(cmd: list[str], *args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        for i, part in enumerate(cmd):
            if part == "-o" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(hayabusa_json + "\n", encoding="utf-8")
                break
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    binary = tmp_path / "hayabusa"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(hayabusa_path=str(binary)),
    )

    log = validate_log_file(_make_evtx_file(tmp_path))
    ingest_evtx_hybrid(log, db, table_name="view_test")

    row = db.execute(f'SELECT * FROM "{_CORRELATION_VIEW_NAME}"').fetchone()
    assert row is not None

    cols = [desc[0] for desc in db.execute(f'DESCRIBE "{_CORRELATION_VIEW_NAME}"').fetchall()]
    assert "raw_message" in cols
    assert "raw_source_ip" in cols

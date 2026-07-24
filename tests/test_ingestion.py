"""Tests for the DuckDB ingestion adapters."""

import subprocess
from pathlib import Path
from subprocess import CalledProcessError, TimeoutExpired

import pytest

from ovs_logs.config.settings import EVTXToolSettings, Settings
from ovs_logs.core.errors import BinaryNotFoundError, IngestionError
from ovs_logs.core.ingestion import adapters
from ovs_logs.core.ingestion.adapters import (
    EVTX_CSV_FIELDNAMES,
    LoadResult,
    load_csv,
    load_evtx,
    load_evtx_via_evtxecmd,
    load_evtx_via_hayabusa,
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
    evtxecmd_path: str = "EvtxECmd",
    timeout_seconds: int = 300,
) -> Settings:
    """Return a Settings with custom EVTX tool paths."""
    return Settings(
        evtx_tools=EVTXToolSettings(
            hayabusa_path=hayabusa_path,
            evtxecmd_path=evtxecmd_path,
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


def test_load_evtx_via_evtxecmd(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(evtxecmd_path="fake-evtxecmd"),
    )

    output_csv = "Timestamp,Computer,EventId,Channel\n2024-01-01T00:00:00,HOST,4624,Security\n"

    def fake_run(cmd, *args, **kwargs):
        csvf = None
        csv_dir = None
        for i, part in enumerate(cmd):
            if part == "--csvf" and i + 1 < len(cmd):
                csvf = cmd[i + 1]
            if part == "--csv" and i + 1 < len(cmd):
                csv_dir = cmd[i + 1]
        if csv_dir and csvf:
            Path(csv_dir, csvf).write_text(output_csv, encoding="utf-8")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = load_evtx_via_evtxecmd(log, db, table_name="test_evtxecmd")

    assert result.table_name == "test_evtxecmd"
    assert result.row_count == 1
    columns = schema_columns(result.schema)
    assert "timestamp" in columns
    assert "computer" in columns


def test_load_evtx_via_evtxecmd_binary_not_found(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(evtxecmd_path="nonexistent-evtxecmd"),
    )

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("No such file")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(BinaryNotFoundError, match="EvtxECmd binary not found"):
        load_evtx_via_evtxecmd(log, db)


def test_load_evtx_via_evtxecmd_process_failure(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(evtxecmd_path="fake-evtxecmd"),
    )

    def fake_run(*args, **kwargs):
        raise CalledProcessError(returncode=1, cmd=["EvtxECmd"], stderr="error")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="EvtxECmd failed"):
        load_evtx_via_evtxecmd(log, db)


def test_load_evtx_via_evtxecmd_timeout(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(evtxecmd_path="fake-evtxecmd", timeout_seconds=10),
    )

    def fake_run(*args, **kwargs):
        raise TimeoutExpired(cmd=["EvtxECmd"], timeout=10)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="EvtxECmd timed out"):
        load_evtx_via_evtxecmd(log, db)


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


def test_load_evtx_via_evtxecmd_permission_error(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(evtxecmd_path="non-executable-evtxecmd"),
    )

    def fake_run(*args, **kwargs):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="EvtxECmd is not executable"):
        load_evtx_via_evtxecmd(log, db)


def test_load_evtx_via_evtxecmd_missing_output(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file = _make_evtx_file(tmp_path)
    log = validate_log_file(file)

    monkeypatch.setattr(
        "ovs_logs.core.ingestion.adapters.settings",
        _custom_settings(evtxecmd_path="fake-evtxecmd"),
    )

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=["EvtxECmd"], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(IngestionError, match="EvtxECmd produced no output"):
        load_evtx_via_evtxecmd(log, db)

"""Tests for the DuckDB ingestion adapters."""

from pathlib import Path
from typing import Sequence

import pytest

from ovs_logs.core.database import Database
from ovs_logs.core.ingestion.adapters import (
    LoadResult,
    load_csv,
    load_evtx,
    load_json,
    load_text_log,
)
from ovs_logs.core.validation import LogFile, validate_log_file


@pytest.fixture
def db():
    """In-memory DuckDB instance for adapter tests."""
    with Database(":memory:") as conn:
        yield conn


def _schema_columns(schema: Sequence[tuple[str, str]]) -> set[str]:
    return {name.lower() for name, _ in schema}


def test_load_csv(db, tmp_path: Path) -> None:
    file = tmp_path / "sample.csv"
    file.write_text("timestamp,client_ip,status\n2024-01-01T00:00:00,1.2.3.4,200\n2024-01-01T00:01:00,5.6.7.8,404\n")

    log = validate_log_file(file)
    result = load_csv(log, db, table_name="test_csv")

    assert isinstance(result, LoadResult)
    assert result.table_name == "test_csv"
    assert result.row_count == 2
    assert {"timestamp", "client_ip", "status"}.issubset(_schema_columns(result.schema))


def test_load_json(db, tmp_path: Path) -> None:
    file = tmp_path / "sample.json"
    file.write_text(
        '[{"id":1,"event":"login","ip":"1.2.3.4"},'
        '{"id":2,"event":"logout","ip":"5.6.7.8"}]'
    )

    log = validate_log_file(file)
    result = load_json(log, db, table_name="test_json")

    assert result.table_name == "test_json"
    assert result.row_count == 2
    assert {"id", "event", "ip"}.issubset(_schema_columns(result.schema))


def test_load_text_log(db, tmp_path: Path) -> None:
    file = tmp_path / "sample.log"
    file.write_text("line one\nline two\nline three\n")

    log = validate_log_file(file)
    result = load_text_log(log, db, table_name="test_log")

    assert result.table_name == "test_log"
    assert result.row_count == 3
    assert "line" in _schema_columns(result.schema)


def test_load_evtx_is_stub(db, tmp_path: Path) -> None:
    file = tmp_path / "sample.evtx"
    file.write_bytes(b"EVT\x00...")

    log = validate_log_file(file)
    assert log.format == "evtx"
    assert log.needs_conversion

    with pytest.raises(NotImplementedError):
        load_evtx(log, db, table_name="test_evtx")

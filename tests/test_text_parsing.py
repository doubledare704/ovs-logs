"""Tests for structured text-log parsing."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path

import duckdb
import pytest

from ovs_logs.config.settings import TextParseConfig
from ovs_logs.core.database import Database
from ovs_logs.core.ingestion.adapters import load_text_log
from ovs_logs.core.text_parsing import parse_text_log
from ovs_logs.core.validation import validate_log_file

# Constants for test assertions to avoid magic values (PLR2004)
EXPECTED_ROW_COUNT = 2
LIMIT_COUNT = 3
REUSE_COUNT = 2
COMPAT_COUNT = 1


@pytest.fixture
def db() -> Iterator[duckdb.DuckDBPyConnection]:
    with Database(":memory:") as conn:
        yield conn


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines), encoding="utf-8")


def _schema_columns(schema: Sequence[tuple[str, str]]) -> set[str]:
    return {name.lower() for name, _ in schema}


def test_parse_web_access_log(db, tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    _write_lines(
        path,
        [
            '10.0.0.1 - - [14/Nov/2023:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024',
            '10.0.0.2 - - [14/Nov/2023:12:01:00 +0000] "POST /api/login HTTP/1.1" 401 512',
        ],
    )
    log = validate_log_file(path)
    result = parse_text_log(log, db, table_name="web_events")
    assert result.row_count == EXPECTED_ROW_COUNT
    assert "timestamp" in _schema_columns(result.schema)
    assert "source_ip" in _schema_columns(result.schema)
    rows = db.execute('SELECT timestamp, source_ip, status_code, event_type FROM "web_events"').fetchall()
    assert rows[0][0] == "14/Nov/2023:12:00:00 +0000"
    assert rows[0][1] == "10.0.0.1"
    assert rows[0][2] == 200
    assert rows[0][3] == "GET"


def test_parse_syslog(db, tmp_path: Path) -> None:
    path = tmp_path / "syslog"
    _write_lines(
        path,
        [
            "Jan 15 08:00:00 srv-01 sshd[1234]: Failed password for alice from 10.0.0.5 port 22 ssh2",
            "Jan 15 08:01:00 srv-01 systemd[1]: Started Session 1 of user root.",
        ],
    )
    log = validate_log_file(path)
    result = parse_text_log(log, db, table_name="syslog_events")
    assert result.row_count == EXPECTED_ROW_COUNT
    rows = db.execute('SELECT timestamp, source_ip, event_type FROM "syslog_events"').fetchall()
    assert rows[0][0] == "Jan 15 08:00:00"
    assert rows[0][1] == "10.0.0.5"
    assert rows[0][2] == "sshd"
    assert rows[1][2] == "systemd"


def test_parse_jsonline(db, tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"ts":"2024-01-01T00:00:00Z","level":"INFO","component":"api","msg":"ok","src_ip":"1.2.3.4","status":200,"duration_ms":10}\n'
        '{"ts":"2024-01-01T00:01:00Z","level":"ERROR","component":"ingest","msg":"fail","src_ip":"5.6.7.8","status":500,"duration_ms":250}\n',
        encoding="utf-8",
    )
    log = validate_log_file(path)
    result = parse_text_log(log, db, table_name="json_events")
    assert result.row_count == EXPECTED_ROW_COUNT
    rows = db.execute('SELECT timestamp, source_ip, status_code, event_type FROM "json_events"').fetchall()
    assert rows[0][0] == "2024-01-01T00:00:00Z"
    assert rows[0][1] == "1.2.3.4"
    assert rows[0][2] == 200
    assert rows[0][3] == "api"


def test_parse_ambiguous_fallback(db, tmp_path: Path) -> None:
    path = tmp_path / "weird.txt"
    _write_lines(path, ["[00:00:00] heartbeat-timeout OK code=12 len=300", "[00:01:00] gc-pause WARN code=7 len=120"])
    log = validate_log_file(path)
    result = parse_text_log(log, db, table_name="ambiguous_events")
    assert result.row_count == EXPECTED_ROW_COUNT
    assert _schema_columns(result.schema) == {"line"}
    rows = db.execute('SELECT line FROM "ambiguous_events"').fetchall()
    assert rows[0][0] == "[00:00:00] heartbeat-timeout OK code=12 len=300"


def test_structured_false_returns_raw(db, tmp_path: Path) -> None:
    path = tmp_path / "plain.txt"
    _write_lines(path, ["line one", "line two"])
    log = validate_log_file(path)
    result = parse_text_log(log, db, table_name="raw_table", config=TextParseConfig(structured=False))
    assert result.row_count == EXPECTED_ROW_COUNT
    assert _schema_columns(result.schema) == {"line"}
    rows = db.execute('SELECT line FROM "raw_table"').fetchall()
    assert rows[0][0] == "line one"


def test_max_lines_per_file_respected_when_structured_false(db, tmp_path: Path) -> None:
    """Regression: line limit must apply even when structured parsing is off.

    Previously, ``max_lines_per_file`` was bypassed whenever
    ``config.structured`` was false because the early-return path ran before
    the LIMIT rebuild. See PR #9 review feedback (gemini-code-assist).
    """
    path = tmp_path / "many.txt"
    _write_lines(path, [f"line {i}" for i in range(10)])
    log = validate_log_file(path)
    result = parse_text_log(
        log,
        db,
        table_name="limited_table",
        config=TextParseConfig(structured=False, max_lines_per_file=3),
    )
    assert result.row_count == LIMIT_COUNT
    rows = db.execute('SELECT line FROM "limited_table"').fetchall()
    assert [r[0] for r in rows] == ["line 0", "line 1", "line 2"]


def test_no_matching_pattern_returns_raw_table(db, tmp_path: Path) -> None:
    path = tmp_path / "garbage.txt"
    _write_lines(path, ["alpha beta gamma", "delta epsilon zeta"])
    log = validate_log_file(path)
    result = parse_text_log(log, db, table_name="garbage_table")
    assert result.row_count == EXPECTED_ROW_COUNT
    assert _schema_columns(result.schema) == {"line"}
    rows = db.execute('SELECT line FROM "garbage_table"').fetchall()
    assert rows[0][0] == "alpha beta gamma"


def test_temp_csv_cleanup_on_success(db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    path = tmp_path / "clean.log"
    _write_lines(path, ['10.0.0.1 - - [14/Nov/2023:12:00:00 +0000] "GET / HTTP/1.1" 200 10'])
    log = validate_log_file(path)
    parse_text_log(log, db, table_name="clean_table")
    tmp_files = list(tmp_path.glob("*.csv"))
    assert not tmp_files


def test_existing_table_replaced(db, tmp_path: Path) -> None:
    path = tmp_path / "dup.log"
    _write_lines(
        path,
        [
            '{"ts":"2024-01-01T00:00:00Z","level":"INFO","component":"api","msg":"hi","src_ip":"1.2.3.4","status":200,"duration_ms":1}'
        ],
    )
    log = validate_log_file(path)
    parse_text_log(log, db, table_name="reuse_table")
    first_count = db.execute('SELECT COUNT(*) FROM "reuse_table"').fetchone()[0]
    assert first_count == 1
    _write_lines(
        path,
        [
            '{"ts":"2024-01-01T00:00:00Z","level":"INFO","component":"api","msg":"hi","src_ip":"1.2.3.4","status":200,"duration_ms":1}',
            '{"ts":"2024-01-01T00:01:00Z","level":"ERROR","component":"ingest","msg":"bye","src_ip":"5.6.7.8","status":500,"duration_ms":2}',
        ],
    )
    log = validate_log_file(path)
    parse_text_log(log, db, table_name="reuse_table")
    count = db.execute('SELECT COUNT(*) FROM "reuse_table"').fetchone()[0]
    assert count == REUSE_COUNT


def test_load_text_log_compat(db, tmp_path: Path) -> None:
    path = tmp_path / "legacy.log"
    _write_lines(path, ["raw line"])
    log = validate_log_file(path)
    result = load_text_log(log, db, table_name="legacy")
    assert result.row_count == COMPAT_COUNT
    assert _schema_columns(result.schema) == {"line"}

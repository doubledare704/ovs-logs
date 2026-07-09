"""Tests for structured text-log parsing."""

from __future__ import annotations

import re
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
    assert rows[0][2] == "200"
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
    assert rows[0][2] == "200"
    assert rows[0][3] == "api"


def test_parse_nginx_json_access_log(db, tmp_path: Path) -> None:
    path = tmp_path / "nginx.json"
    path.write_text(
        '{"time": "17/May/2015:08:05:32 +0000", "remote_ip": "192.168.1.1", "remote_user": "-", '
        '"request": "GET /downloads/product_1 HTTP/1.1", "response": 200, "bytes": 1024, '
        '"referrer": "-", "agent": "curl"}\n'
        '{"time": "17/May/2015:08:06:00 +0000", "remote_ip": "192.168.1.2", "remote_user": "-", '
        '"request": "POST /api/login HTTP/1.1", "response": 404, "bytes": 512, '
        '"referrer": "-", "agent": "curl"}\n',
        encoding="utf-8",
    )
    log = validate_log_file(path)
    result = parse_text_log(log, db, table_name="nginx_events")
    assert result.row_count == EXPECTED_ROW_COUNT
    rows = db.execute('SELECT timestamp, source_ip, status_code, event_type FROM "nginx_events"').fetchall()
    assert rows[0][0] == "17/May/2015:08:05:32 +0000"
    assert rows[0][1] == "192.168.1.1"
    assert rows[0][2] == "200"
    assert rows[0][3] == "GET"
    assert rows[1][3] == "POST"


def test_parse_nginx_plus_metrics_best_effort(db, tmp_path: Path) -> None:
    path = tmp_path / "nginxplus.json"
    path.write_text(
        '{"timestamp": 1431433200, "server_zones": {"example.com": {"requests": 100}}, '
        '"upstreams": {"backend": {"requests": 50}}}\n',
        encoding="utf-8",
    )
    log = validate_log_file(path)
    result = parse_text_log(log, db, table_name="nginxplus_events")
    assert result.row_count == COMPAT_COUNT
    columns = _schema_columns(result.schema)
    assert "timestamp" in columns
    assert "raw_message" in columns
    rows = db.execute('SELECT timestamp, raw_message FROM "nginxplus_events"').fetchall()
    assert rows[0][0] == "1431433200"
    assert "server_zones" in rows[0][1]


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


def test_load_text_log_preserves_commas_and_quotes(db, tmp_path: Path) -> None:
    """A line containing commas/quotes must stay a single verbatim ``line`` column.

    Regression guard for the DuckDB single-column direct read: embedded CSV
    metacharacters must not split or mangle the raw log line.
    """
    path = tmp_path / "messy.log"
    tricky = '10.0.0.1 - - [08/Jul/2026:10:00:00 +0300] "GET /a,b?x=\\"1\\" HTTP/1.1" 200 123'
    _write_lines(path, [tricky])
    log = validate_log_file(path)
    result = load_text_log(log, db, table_name="messy")
    assert result.row_count == 1
    assert _schema_columns(result.schema) == {"line"}
    row = db.execute('SELECT line FROM "messy"').fetchone()
    assert row[0] == tricky


def test_structured_extraction_matches_canonical_regex(db, tmp_path: Path) -> None:
    """The SQL ``regexp_extract`` path must match the canonical per-field regexes.

    Parity guard ensuring the DuckDB-native extraction produces the same values
    the previous Python regex loop did, for each supported format.
    """

    cases = {
        "web": (
            '10.0.0.1 - - [08/Jul/2026:10:00:00 +0300] "GET /index.html HTTP/1.1" 200 1024',
            {
                "timestamp": r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4})\]",
                "source_ip": r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
                "status_code": r'"\s+(\d{3})\s+',
                "event_type": r'"(\w+)\s+\S+\s+HTTP',
            },
        ),
        "syslog": (
            "Jan 15 08:00:00 srv-01 sshd[1234]: Failed password for alice from 10.0.0.5 port 22",
            {
                "timestamp": r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
                "source_ip": r"(?:from\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
                "event_type": r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+([A-Za-z0-9_.-]+)(?:\[\d+\])?:",
            },
        ),
        "jsonline": (
            '{"ts":"2024-01-01T00:00:00Z","component":"api","src_ip":"1.2.3.4","status":200}',
            {
                "timestamp": r'"(?:ts|timestamp)"\s*:\s*"([^"]+)"',
                "source_ip": r'"(?:src_ip|source_ip|ip)"\s*:\s*"([^"]+)"',
                "status_code": r'"(?:status|status_code)"\s*:\s*(\d+)',
                "event_type": r'"(?:component|event_type|event|method)"\s*:\s*"([^"]+)"',
            },
        ),
    }
    for fmt, (line, patterns) in cases.items():
        path = tmp_path / f"{fmt}.log"
        _write_lines(path, [line])
        log = validate_log_file(path)
        result = parse_text_log(log, db, table_name=f"{fmt}_p")
        rows = db.execute(f'SELECT * FROM "{result.table_name}"').fetchall()
        assert len(rows) == 1
        fields = {name: value for (name, _), value in zip(result.schema, rows[0], strict=True)}
        for field, pattern in patterns.items():
            expected = re.search(pattern, line)
            expected = expected.group(1) if expected else ""
            assert fields[field] == expected, f"{fmt}.{field}: {fields[field]!r} != {expected!r}"


def test_load_text_log_compat(db, tmp_path: Path) -> None:
    path = tmp_path / "legacy.log"
    _write_lines(path, ["raw line"])
    log = validate_log_file(path)
    result = load_text_log(log, db, table_name="legacy")
    assert result.row_count == COMPAT_COUNT
    assert _schema_columns(result.schema) == {"line"}

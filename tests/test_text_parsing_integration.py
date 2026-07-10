"""Integration tests for structured text-log parsing in CLI and UI flows."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import duckdb
from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner, Result

from ovs_logs.cli.main import app
from ovs_logs.core.database import Database

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"
runner = CliRunner()


def _make_db(tmp_path: Path, table_sql: list[tuple[str, str]]) -> Path:
    """Create a temp DuckDB file with the given (name, ddl) user tables."""
    db = tmp_path / "ovs_logs.db"
    with duckdb.connect(str(db)) as conn:
        for name, ddl in table_sql:
            conn.execute(f'CREATE TABLE "{name}" AS {ddl}')
    return db


def _make_temp_file(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def _invoke_ingest(file_path: Path, file_type: str, db: Path, table: str) -> Result:
    """Helper to invoke the CLI ingest command."""
    return runner.invoke(
        app,
        [
            "ingest",
            "--file",
            str(file_path),
            "--type",
            file_type,
            "--db",
            str(db),
            "--table",
            table,
        ],
    )


def _describe_columns(conn: duckdb.DuckDBPyConnection, table: str) -> dict[str, str]:
    """Helper to describe columns of a given table."""
    schema = conn.execute(f'DESCRIBE "{table}"').fetchall()
    return {row[0]: row[1] for row in schema}


def _run_ui_ingest(tmp_path: Path, log_file: Path) -> AppTest:
    """Helper to run Streamlit AppTest ingestion."""
    db = _make_db(tmp_path, [("alpha", "SELECT 1")])
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input(key="db_path").set_value(str(db)).run()

    content = log_file.read_bytes()
    at.file_uploader(key="log_file_uploader").upload(log_file.name, content).run()
    at.button(key="process_ingest").click().run()
    return at


def test_cli_ingest_structured_web_access_log(tmp_path: Path) -> None:
    """CLI: web access logs should normalize into the events table."""
    access_log = _make_temp_file(
        tmp_path,
        "access.log",
        '192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1234\n'
        '192.168.1.2 - - [01/Jan/2024:00:01:00 +0000] "POST /login HTTP/1.1" 404 567\n',
    )
    db = tmp_path / "test.db"

    result = _invoke_ingest(access_log, "log", db, "raw_access")

    assert result.exit_code == 0, result.output
    assert "Loaded 2 rows" in result.output

    with Database(str(db)) as conn:
        tables = conn.execute("SHOW TABLES").fetchall()
        table_names = [t[0] for t in tables]
        assert "raw_access" in table_names
        assert "events" in table_names

        columns = _describe_columns(conn, "events")
        assert "event_timestamp" in columns
        assert "source_ip" in columns
        assert "status_code" in columns
        assert "event_type" in columns

        rows = conn.execute("SELECT event_timestamp, source_ip, status_code, event_type FROM events").fetchall()
        expected_row_count = 2
        expected_status_codes = {200, 404}
        expected_source_ips = {"192.168.1.1", "192.168.1.2"}
        assert len(rows) == expected_row_count
        assert {row[2] for row in rows} == expected_status_codes
        assert {row[1] for row in rows} == expected_source_ips
        # Apache combined timestamps must parse into event_timestamp (regression)
        assert all(row[0] is not None for row in rows)
        assert rows[0][0] == datetime(2024, 1, 1, 0, 0, 0)


def test_cli_ingest_ambiguous_text_fallback_raw(tmp_path: Path) -> None:
    """CLI: ambiguous text should fall back to a raw single-column table."""
    ambiguous = _make_temp_file(
        tmp_path,
        "ambiguous.txt",
        "This is just some random text.\nNothing here matches any pattern.\n",
    )
    db = tmp_path / "test.db"

    result = _invoke_ingest(ambiguous, "txt", db, "raw_ambiguous")

    assert result.exit_code == 0, result.output
    assert "Loaded 2 rows" in result.output

    with Database(str(db)) as conn:
        tables = conn.execute("SHOW TABLES").fetchall()
        table_names = [t[0] for t in tables]
        assert "raw_ambiguous" in table_names
        assert "events" not in table_names

        columns = _describe_columns(conn, "raw_ambiguous")
        assert "line" in columns
        assert len(columns) == 1


def test_cli_ingest_syslog_structured(tmp_path: Path) -> None:
    """CLI: syslog entries should normalize into structured event fields."""
    syslog = _make_temp_file(
        tmp_path,
        "syslog.log",
        "Jan  1 00:00:00 hostname sshd[1234]: Accepted password for user1 from 192.168.1.100\n"
        "Jan  1 00:01:00 hostname sshd[1235]: Failed password for user2 from 10.0.0.1\n",
    )
    db = tmp_path / "test.db"

    result = _invoke_ingest(syslog, "log", db, "raw_syslog")

    assert result.exit_code == 0, result.output
    assert "Loaded 2 rows" in result.output

    with Database(str(db)) as conn:
        columns = _describe_columns(conn, "events")
        assert "event_timestamp" in columns
        assert "source_ip" in columns
        assert "event_type" in columns

        rows = conn.execute("SELECT event_timestamp, source_ip, event_type FROM events").fetchall()
        expected_rows = 2
        assert len(rows) == expected_rows
        assert rows[0][1] == "192.168.1.100"
        assert rows[1][1] == "10.0.0.1"


def test_cli_ingest_jsonline_structured(tmp_path: Path) -> None:
    """CLI: JSON Lines input should normalize into structured event columns."""
    jsonline = _make_temp_file(
        tmp_path,
        "app.txt",
        '{"ts": "2024-01-01T00:00:00Z", "src_ip": "1.2.3.4", "status": 200, "component": "GET"}\n'
        '{"ts": "2024-01-01T00:01:00Z", "src_ip": "5.6.7.8", "status": 500, "component": "POST"}\n',
    )
    db = tmp_path / "test.db"

    result = _invoke_ingest(jsonline, "txt", db, "raw_jsonline")

    assert result.exit_code == 0, result.output
    assert "Loaded 2 rows" in result.output

    with Database(str(db)) as conn:
        columns = _describe_columns(conn, "events")
        assert "event_timestamp" in columns
        assert "source_ip" in columns
        assert "status_code" in columns
        assert "event_type" in columns

        rows = conn.execute("SELECT event_timestamp, source_ip, status_code, event_type FROM events").fetchall()
        expected_rows = 2
        expected_status_codes: set[int] = {200, 500}
        assert len(rows) == expected_rows
        assert rows[0][1] == "1.2.3.4"
        assert rows[0][2] == expected_status_codes.pop()
        assert rows[1][1] == "5.6.7.8"
        assert rows[1][2] == expected_status_codes.pop()


def test_ui_upload_web_access_log_structured_preview(tmp_path: Path) -> None:
    """UI: uploaded web access logs should show structured preview columns."""
    access_log = _make_temp_file(
        tmp_path,
        "access.log",
        '192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1234\n'
        '192.168.1.2 - - [01/Jan/2024:00:01:00 +0000] "POST /login HTTP/1.1" 404 567\n',
    )

    at = _run_ui_ingest(tmp_path, access_log)

    uploaded_files = at.session_state["uploaded_files"]
    ingested = [f for f in uploaded_files if f["status"] == "ingested"]
    assert len(ingested) == 1
    assert ingested[0]["name"] == "access.log"

    dataframes = at.dataframe
    assert len(dataframes) > 0

    preview_df = next(
        df.value
        for df in dataframes
        if any(c in df.value.columns for c in ("timestamp", "source_ip", "status_code", "event_type"))
    )
    assert "timestamp" in preview_df.columns
    assert "source_ip" in preview_df.columns
    assert "status_code" in preview_df.columns
    assert "event_type" in preview_df.columns


def test_ui_upload_ambiguous_text_fallback_warning(tmp_path: Path) -> None:
    """UI: ambiguous text should fall back to a raw preview table."""
    ambiguous = _make_temp_file(
        tmp_path,
        "ambiguous.txt",
        "This is just some random text.\nNothing here matches any pattern.\n",
    )

    at = _run_ui_ingest(tmp_path, ambiguous)

    uploaded_files = at.session_state["uploaded_files"]
    ingested = [f for f in uploaded_files if f["status"] == "ingested"]
    assert len(ingested) == 1
    assert ingested[0]["name"] == "ambiguous.txt"

    dataframes = at.dataframe
    assert len(dataframes) > 0

    preview_df = next(df.value for df in dataframes if "line" in df.value.columns)
    assert "line" in preview_df.columns
    assert "timestamp" not in preview_df.columns
    assert "source_ip" not in preview_df.columns
    assert "status_code" not in preview_df.columns
    assert "event_type" not in preview_df.columns


def test_ui_upload_syslog_structured_preview(tmp_path: Path) -> None:
    """UI: syslog uploads should show structured preview columns."""
    syslog = _make_temp_file(
        tmp_path,
        "syslog.log",
        "Jan  1 00:00:00 hostname sshd[1234]: Accepted password for user1 from 192.168.1.100\n"
        "Jan  1 00:01:00 hostname sshd[1235]: Failed password for user2 from 10.0.0.1\n",
    )

    at = _run_ui_ingest(tmp_path, syslog)

    uploaded_files = at.session_state["uploaded_files"]
    ingested = [f for f in uploaded_files if f["status"] == "ingested"]
    assert len(ingested) == 1

    dataframes = at.dataframe
    assert len(dataframes) > 0

    preview_df = next(
        df.value for df in dataframes if any(c in df.value.columns for c in ("timestamp", "source_ip", "event_type"))
    )
    assert "timestamp" in preview_df.columns
    assert "source_ip" in preview_df.columns
    assert "event_type" in preview_df.columns


def test_ui_upload_jsonline_structured_preview(tmp_path: Path) -> None:
    """UI: JSON Lines uploads should show structured preview columns."""
    jsonline = _make_temp_file(
        tmp_path,
        "app.txt",
        '{"ts": "2024-01-01T00:00:00Z", "src_ip": "1.2.3.4", "status": 200, "component": "GET"}\n'
        '{"ts": "2024-01-01T00:01:00Z", "src_ip": "5.6.7.8", "status": 500, "component": "POST"}\n',
    )

    at = _run_ui_ingest(tmp_path, jsonline)

    uploaded_files = at.session_state["uploaded_files"]
    ingested = [f for f in uploaded_files if f["status"] == "ingested"]
    assert len(ingested) == 1

    dataframes = at.dataframe
    assert len(dataframes) > 0

    preview_df = next(
        df.value
        for df in dataframes
        if any(c in df.value.columns for c in ("timestamp", "source_ip", "status_code", "event_type"))
    )
    assert "timestamp" in preview_df.columns
    assert "source_ip" in preview_df.columns
    assert "status_code" in preview_df.columns
    assert "event_type" in preview_df.columns


def test_ui_upload_nginx_jsonline_structured_preview(tmp_path: Path) -> None:
    """UI: nginx JSON-line uploads should show structured preview columns."""
    nginx_json = _make_temp_file(
        tmp_path,
        "nginx.txt",
        '{"time": "17/May/2015:08:05:32 +0000", "remote_ip": "192.168.1.1", "remote_user": "-", '
        '"request": "GET /downloads/product_1 HTTP/1.1", "response": 200, "bytes": 1024, '
        '"referrer": "-", "agent": "curl"}\n'
        '{"time": "17/May/2015:08:06:00 +0000", "remote_ip": "192.168.1.2", "remote_user": "-", '
        '"request": "POST /api/login HTTP/1.1", "response": 404, "bytes": 512, '
        '"referrer": "-", "agent": "curl"}\n',
    )

    at = _run_ui_ingest(tmp_path, nginx_json)

    uploaded_files = at.session_state["uploaded_files"]
    ingested = [f for f in uploaded_files if f["status"] == "ingested"]
    assert len(ingested) == 1

    dataframes = at.dataframe
    assert len(dataframes) > 0

    preview_df = next(
        df.value
        for df in dataframes
        if any(c in df.value.columns for c in ("timestamp", "source_ip", "status_code", "event_type"))
    )
    assert "timestamp" in preview_df.columns
    assert "source_ip" in preview_df.columns
    assert "status_code" in preview_df.columns
    assert "event_type" in preview_df.columns
    assert "GET" in preview_df["event_type"].values

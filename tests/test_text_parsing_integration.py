"""Integration tests for structured text-log parsing in CLI and UI flows."""

from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner

from ovs_logs.cli.main import app
from ovs_logs.core.database import Database

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"
runner = CliRunner()


def _make_db(tmp_path: Path, table_sql: list[tuple[str, str]]) -> Path:
    """Create a temp DuckDB file with the given (name, ddl) user tables."""
    import duckdb

    db = tmp_path / "ovs_logs.db"
    with duckdb.connect(str(db)) as conn:
        for name, ddl in table_sql:
            conn.execute(f'CREATE TABLE "{name}" AS {ddl}')
    return db


def _make_temp_file(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def _invoke_ingest(file_path: Path, file_type: str, db: Path, table: str):
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


def _describe_columns(conn: Database, table: str) -> dict[str, str]:
    return {row[0]: row[1] for row in conn.execute(f'DESCRIBE "{table}"').fetchall()}


def _run_ui_ingest(tmp_path: Path, log_path: Path) -> AppTest:
    """Drive the Streamlit app: set db path, upload file, click Process & Analyze."""
    db = _make_db(tmp_path, [("alpha", "SELECT 1")])
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input(key="db_path").set_value(str(db)).run()

    content = log_path.read_bytes()
    at.file_uploader(key="log_file_uploader").upload(log_path.name, content).run()

    at.button(key="process_ingest").click().run()
    return at


def test_cli_ingest_structured_web_access_log(tmp_path: Path) -> None:
    """CLI: ovs-log ingest --file access.log --type log → events table has structured fields."""
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

        events_tables = [t for t in table_names if t == "events"]
        assert events_tables, "events table should be created after ingestion"

        raw_columns = _describe_columns(conn, "raw_access")
        assert "timestamp" in raw_columns, "raw table should have timestamp column"
        assert "source_ip" in raw_columns, "raw table should have source_ip column"
        assert "status_code" in raw_columns, "raw table should have status_code column"
        assert "event_type" in raw_columns, "raw table should have event_type column"

        events_columns = _describe_columns(conn, "events")
        assert "event_timestamp" in events_columns
        assert "source_ip" in events_columns
        assert "status_code" in events_columns
        assert "event_type" in events_columns

        rows = conn.execute(
            "SELECT event_timestamp, source_ip, status_code, event_type FROM events"
        ).fetchall()
        assert len(rows) == 2
        assert rows[0][1] == "192.168.1.1"
        assert int(rows[0][2]) == 200
        assert rows[1][1] == "192.168.1.2"
        assert int(rows[1][2]) == 404


def test_cli_ingest_ambiguous_text_fallback_raw(tmp_path: Path) -> None:
    """CLI: ovs-log ingest --file ambiguous.txt --type txt → fallback raw path."""
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

        assert "raw_ambiguous" in table_names, "raw table should be created"

        columns = _describe_columns(conn, "raw_ambiguous")
        assert "line" in columns
        assert len(columns) == 1


def test_cli_ingest_syslog_structured(tmp_path: Path) -> None:
    """CLI: syslog format should be parsed with structured fields."""
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
        tables = conn.execute("SHOW TABLES").fetchall()
        table_names = [t[0] for t in tables]
        assert "events" in table_names

        raw_columns = _describe_columns(conn, "raw_syslog")
        assert "timestamp" in raw_columns
        assert "source_ip" in raw_columns
        assert "event_type" in raw_columns

        rows = conn.execute(
            "SELECT event_timestamp, source_ip, event_type FROM events"
        ).fetchall()
        assert len(rows) == 2
        assert rows[0][1] == "192.168.1.100"
        assert rows[1][1] == "10.0.0.1"


def test_cli_ingest_jsonline_structured(tmp_path: Path) -> None:
    """CLI: JSON Lines format should be parsed with structured fields."""
    jsonline = _make_temp_file(
        tmp_path,
        "app.jsonl",
        '{"timestamp": "2024-01-01T00:00:00Z", "source_ip": "1.2.3.4", "status_code": 200, "event_type": "GET"}\n'
        '{"timestamp": "2024-01-01T00:01:00Z", "source_ip": "5.6.7.8", "status_code": 500, "event_type": "POST"}\n',
    )
    db = tmp_path / "test.db"

    result = _invoke_ingest(jsonline, "txt", db, "raw_jsonline")

    assert result.exit_code == 0, result.output
    assert "Loaded 2 rows" in result.output

    with Database(str(db)) as conn:
        tables = conn.execute("SHOW TABLES").fetchall()
        table_names = [t[0] for t in tables]
        assert "events" in table_names

        raw_columns = _describe_columns(conn, "raw_jsonline")
        assert "timestamp" in raw_columns
        assert "source_ip" in raw_columns
        assert "status_code" in raw_columns
        assert "event_type" in raw_columns

        rows = conn.execute(
            "SELECT event_timestamp, source_ip, status_code, event_type FROM events"
        ).fetchall()
        assert len(rows) == 2
        assert rows[0][1] == "1.2.3.4"
        assert int(rows[0][2]) == 200
        assert rows[1][1] == "5.6.7.8"
        assert int(rows[1][2]) == 500


def test_ui_upload_web_access_log_structured_preview(tmp_path: Path) -> None:
    """UI: Upload web access log → structured events table fields visible in preview."""
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
    assert len(dataframes) > 0, "Should have dataframe preview of ingested table"

    preview_df = dataframes[0].value
    assert "timestamp" in preview_df.columns
    assert "source_ip" in preview_df.columns
    assert "status_code" in preview_df.columns
    assert "event_type" in preview_df.columns


def test_ui_upload_ambiguous_text_fallback_warning(tmp_path: Path) -> None:
    """UI: Upload ambiguous text → raw table created with single 'line' column."""
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
    assert len(dataframes) > 0, "Should have dataframe preview of raw table"

    preview_df = dataframes[0].value
    assert "line" in preview_df.columns
    assert "timestamp" not in preview_df.columns
    assert "source_ip" not in preview_df.columns
    assert "status_code" not in preview_df.columns
    assert "event_type" not in preview_df.columns


def test_ui_upload_syslog_structured_preview(tmp_path: Path) -> None:
    """UI: Upload syslog → structured events table fields visible in preview."""
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

    preview_df = dataframes[0].value
    assert "timestamp" in preview_df.columns
    assert "source_ip" in preview_df.columns
    assert "event_type" in preview_df.columns


def test_ui_upload_jsonline_structured_preview(tmp_path: Path) -> None:
    """UI: Upload JSON Lines → structured events table fields visible in preview."""
    jsonline = _make_temp_file(
        tmp_path,
        "app.jsonl.txt",
        '{"timestamp": "2024-01-01T00:00:00Z", "source_ip": "1.2.3.4", "status_code": 200, "event_type": "GET"}\n'
        '{"timestamp": "2024-01-01T00:01:00Z", "source_ip": "5.6.7.8", "status_code": 500, "event_type": "POST"}\n',
    )

    at = _run_ui_ingest(tmp_path, jsonline)

    uploaded_files = at.session_state["uploaded_files"]
    ingested = [f for f in uploaded_files if f["status"] == "ingested"]
    assert len(ingested) == 1

    dataframes = at.dataframe
    assert len(dataframes) > 0

    preview_df = dataframes[0].value
    assert "timestamp" in preview_df.columns
    assert "source_ip" in preview_df.columns
    assert "status_code" in preview_df.columns
    assert "event_type" in preview_df.columns

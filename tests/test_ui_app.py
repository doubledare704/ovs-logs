"""Tests for the OVS-Log Streamlit dashboard (src/ovs_logs/ui/app.py)."""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest
from streamlit.testing.v1 import AppTest

from ovs_logs.core.ingestion import adapters as adapters_mod

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"


def _make_db(tmp_path: Path, table_sql: list[tuple[str, str]]) -> Path:
    """Create a temp DuckDB file with the given (name, ddl) user tables."""
    db = tmp_path / "ovs_logs.db"
    with duckdb.connect(str(db)) as conn:
        for name, ddl in table_sql:
            conn.execute(f'CREATE TABLE "{name}" AS {ddl}')
    return db


def test_app_renders_without_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    at = AppTest.from_file(str(APP_PATH)).run()
    assert not at.exception
    # 2 password inputs (AbuseIPDB + LLM) + 1 text input (db path) = 3 in sidebar
    expected_sidebar_inputs = 3
    assert len(at.sidebar.text_input) == expected_sidebar_inputs
    assert at.sidebar.text_input[0].label == "AbuseIPDB API Key"
    assert at.sidebar.text_input[1].label == "LLM API Key"
    assert at.sidebar.text_input[2].label == "Database path"


def test_api_keys_default_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-key-123")
    monkeypatch.setenv("LLM_API_KEY", "llm-key-456")

    at = AppTest.from_file(str(APP_PATH)).run()
    assert at.session_state["ABUSEIPDB_API_KEY"] == "abuse-key-123"
    assert at.session_state["LLM_API_KEY"] == "llm-key-456"
    assert at.sidebar.text_input[0].value == "abuse-key-123"
    assert at.sidebar.text_input[1].value == "llm-key-456"


def test_db_path_defaults_to_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OVS_LOGS_DB_PATH", raising=False)

    at = AppTest.from_file(str(APP_PATH)).run()
    assert at.session_state["db_path"] == ".ovs_logs/ovs_logs.db"
    # The default DB file may or may not exist in the dev environment.
    # - missing file -> error mentioning the path, selected_table cleared
    # - exists but empty -> info "No application tables"
    # - exists with tables -> a table selectbox is rendered
    errors = list(at.sidebar.error)
    if any(".ovs_logs/ovs_logs.db" in e.value for e in errors):
        assert at.session_state.get("selected_table") is None
    else:
        has_no_tables_info = any("No application tables" in i.value for i in at.sidebar.info)
        has_not_found_error = any("not found" in e.value for e in errors)
        has_table_selector = len(at.sidebar.selectbox) > 0
        assert has_no_tables_info or has_not_found_error or has_table_selector


def test_missing_db_shows_error(tmp_path: Path) -> None:
    missing = tmp_path / "nope.db"
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(missing)).run()
    assert any(str(missing) in e.value for e in at.sidebar.error)


def test_recent_tables_lists_user_tables_only(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            ("events_2026", "SELECT 1 AS id"),
            ("indicators", "SELECT 'a' AS ip"),
            # Should be filtered out by the sqlite_ prefix rule:
            ("sqlite_should_hide", "SELECT 1"),
        ],
    )

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()

    sb = at.sidebar.selectbox[0]
    assert sb.label == "Select a table"
    assert "events_2026" in sb.options
    assert "indicators" in sb.options
    assert "sqlite_should_hide" not in sb.options
    assert at.session_state["selected_table"] == sb.value


def test_changing_db_path_refreshes_tables(tmp_path: Path) -> None:
    db_a = _make_db(tmp_path, [("alpha", "SELECT 1")])
    db_b_dir = tmp_path / "other"
    db_b_dir.mkdir()
    db_b = _make_db(db_b_dir, [("beta", "SELECT 1")])

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db_a)).run()
    assert at.sidebar.selectbox[0].options == ["alpha"]

    at.sidebar.text_input[2].set_value(str(db_b)).run()
    assert at.sidebar.selectbox[0].options == ["beta"]
    # selected_table should follow the new list
    assert at.session_state["selected_table"] == "beta"


def test_changing_db_path_clears_stale_table_selection(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [("alpha", "SELECT 1")])
    missing = tmp_path / "missing.db"

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("alpha").run()
    assert at.session_state["selected_table"] == "alpha"

    at.sidebar.text_input[2].set_value(str(missing)).run()
    assert "selected_table" not in at.session_state
    assert len(at.sidebar.selectbox) == 0


def test_selecting_table_persists_to_session_state(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [("alpha", "SELECT 1"), ("beta", "SELECT 2")],
    )
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("beta").run()
    assert at.session_state["selected_table"] == "beta"


def _make_temp_file(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_upload_and_validate_file(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = _make_temp_file(tmp_path, "sample.log", "line1\nline2\n")

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()

    content = file_path.read_bytes()
    at.file_uploader[0].upload(file_path.name, content).run()

    assert any(file_state["name"] == "sample.log" for file_state in at.session_state["uploaded_files"])
    assert any(file_state["status"] == "ready" for file_state in at.session_state["uploaded_files"])
    assert any("line1" in (file_state["preview"] or "") for file_state in at.session_state["uploaded_files"])


def test_duplicate_upload_is_skipped(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = _make_temp_file(tmp_path, "duplicate.log", "line1\nline2\n")

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()

    content = file_path.read_bytes()
    at.file_uploader[0].upload(file_path.name, content).run()
    at.file_uploader[0].upload(file_path.name, content).run()

    uploaded_files = at.session_state["uploaded_files"]
    assert len(uploaded_files) == 1
    assert uploaded_files[0]["name"] == "duplicate.log"


def test_raw_preview_displays_preview_text(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = _make_temp_file(tmp_path, "raw.log", "first line\nsecond line\n")

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()

    content = file_path.read_bytes()
    at.file_uploader[0].upload(file_path.name, content).run()

    assert any(
        file_state["name"] == "raw.log" and file_state["status"] == "ready"
        for file_state in at.session_state["uploaded_files"]
    )
    assert any("first line" in (file_state["preview"] or "") for file_state in at.session_state["uploaded_files"])
    assert any("Upload status:" in info.value and "ready" in info.value for info in at.info)


def test_ingested_table_preview_after_process(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = _make_temp_file(tmp_path, "process.log", "line1\nline2\n")

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()

    content = file_path.read_bytes()
    at.file_uploader[0].upload(file_path.name, content).run()

    at.button[0].click().run()

    uploaded_files = at.session_state["uploaded_files"]
    assert uploaded_files[0]["status"] == "ingested"
    assert uploaded_files[0]["ingest_table"] is not None
    assert uploaded_files[0]["normalized_table"] == "events"
    assert len(at.dataframe) > 0


def test_selected_table_renders_data_preview(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [("alpha", "SELECT 1 AS id, 'x' AS name")])
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("alpha").run()
    assert any(df.value is not None and len(df.value) > 0 for df in at.dataframe)


def test_selected_analyzable_table_renders_indicators(tmp_path: Path) -> None:
    db = _make_db(
        tmp_path,
        [
            (
                "events_like",
                "SELECT '1.2.3.4' AS source_ip, 404 AS status_code, 'GET' AS event_type, "
                "TIMESTAMP '2024-01-01 00:00:00' AS event_timestamp, 'msg' AS raw_message",
            )
        ],
    )
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("events_like").run()
    assert any(df.value is not None and "Type" in df.value.columns for df in at.dataframe)


def test_selected_non_analyzable_table_shows_info(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [("reports", "SELECT 'hello' AS note")])
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("reports").run()
    assert any("No analyzable fields" in info.value for info in at.info)


def test_evtx_upload_preview_shows_records(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = _make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = _make_temp_file(tmp_path, "sample.evtx", "EVT marker bytes")

    class FakeParser:
        def __init__(self, path: str) -> None:
            self.path = path

        def records_json(self):
            return [
                {
                    "event_record_id": 1,
                    "data": {
                        "Event": {
                            "System": {
                                "EventID": {"#text": 4624},
                                "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
                                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                                "Channel": "Security",
                            }
                        }
                    },
                }
            ]

    monkeypatch.setattr(adapters_mod, "PyEvtxParser", FakeParser)

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()

    content = file_path.read_bytes()
    at.file_uploader[0].upload(file_path.name, content).run()

    uploaded_files = at.session_state["uploaded_files"]
    assert any(
        file_state["name"] == "sample.evtx"
        and file_state["status"] == "ready"
        and "EventID=4624" in (file_state["preview"] or "")
        for file_state in uploaded_files
    )


def test_ingested_web_log_shows_potential_signals(tmp_path: Path) -> None:
    db = _make_db(tmp_path, [("alpha", "SELECT 1")])
    access_log = _make_temp_file(
        tmp_path,
        "access.log",
        '192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1234\n'
        '192.168.1.2 - - [01/Jan/2024:00:01:00 +0000] "POST /login HTTP/1.1" 404 567\n',
    )

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()

    content = access_log.read_bytes()
    at.file_uploader[0].upload(access_log.name, content).run()
    at.button[0].click().run()

    has_indicators = any(df.value is not None and "Type" in df.value.columns for df in at.dataframe)
    has_info = any("No suspicious indicators" in info.value or "No analyzable fields" in info.value for info in at.info)
    assert has_indicators or has_info

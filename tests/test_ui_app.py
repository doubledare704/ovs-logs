"""Tests for the OVS-Log Streamlit dashboard (src/ovs_logs/ui/app.py)."""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest
from streamlit.testing.v1 import AppTest

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
    # If it exists, the app should show a selectbox (possibly with "No tables" info).
    # If it doesn't exist, the app should show an error mentioning the path.
    if any(".ovs_logs/ovs_logs.db" in e.value for e in at.sidebar.error):
        assert at.session_state.get("selected_table") is None
    else:
        assert any("No application tables" in i.value for i in at.sidebar.info) or any(
            "not found" in e.value for e in at.sidebar.error
        )


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

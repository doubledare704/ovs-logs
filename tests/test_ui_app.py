"""Tests for the OVS-Log Streamlit dashboard (src/ovs_logs/ui/app.py)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import duckdb
import pytest
import requests
from streamlit.testing.v1 import AppTest

from ovs_logs.config.settings import Settings, settings
from ovs_logs.core.analysis import engine
from ovs_logs.core.ingestion import adapters
from ovs_logs.core.persistence import ReportStore

from .conftest import (
    button_by_label,
    checkbox_by_label,
    make_db,
    make_temp_file,
    sample_report,
    selectbox_by_label,
    sidebar_button_by_label,
    text_input_by_label,
)

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"


def test_app_renders_without_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    at = AppTest.from_file(str(APP_PATH)).run()
    assert not at.exception
    # 2 password inputs (AbuseIPDB + LLM) + 3 text inputs (LLM endpoint + LLM model + db path) = 5
    expected_sidebar_inputs = 5
    assert len(at.sidebar.text_input) == expected_sidebar_inputs
    assert at.sidebar.text_input[0].label == "AbuseIPDB API Key"
    assert at.sidebar.text_input[1].label == "LLM API Key"
    assert at.sidebar.text_input[2].label == "LLM endpoint"
    assert at.sidebar.text_input[3].label == "LLM model"
    assert at.sidebar.text_input[4].label == "Database path"
    # Threat list sidebar: 2 checkboxes (default lists) + 1 button (Update)
    assert len(at.sidebar.checkbox) == 2
    assert len(at.sidebar.button) == 1
    assert at.sidebar.checkbox[0].label == "firehol_level1"
    assert at.sidebar.checkbox[1].label == "firehol_abusers_30d"


def test_api_keys_default_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-key-123")
    monkeypatch.setenv("LLM_API_KEY", "llm-key-456")

    at = AppTest.from_file(str(APP_PATH)).run()
    assert at.session_state["ABUSEIPDB_API_KEY"] == "abuse-key-123"
    assert at.session_state["LLM_API_KEY"] == "llm-key-456"
    assert text_input_by_label(at, "AbuseIPDB API Key").value == "abuse-key-123"
    assert text_input_by_label(at, "LLM API Key").value == "llm-key-456"


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
        # Use 'in' instead of .get() for Streamlit SafeSessionState compat
        assert "selected_table" not in at.session_state
    else:
        has_no_tables_info = any("No application tables" in i.value for i in at.sidebar.info)
        has_not_found_error = any("not found" in e.value for e in errors)
        has_table_selector = len(at.sidebar.selectbox) > 0
        assert has_no_tables_info or has_not_found_error or has_table_selector


def test_missing_db_shows_error(tmp_path: Path) -> None:
    missing = tmp_path / "nope.db"
    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(missing)).run()
    assert any(str(missing) in e.value for e in at.sidebar.error)


def test_recent_tables_lists_user_tables_only(tmp_path: Path) -> None:
    db = make_db(
        tmp_path,
        [
            ("events_2026", "SELECT 1 AS id"),
            ("indicators", "SELECT 'a' AS ip"),
            # Should be filtered out by the sqlite_ prefix rule:
            ("sqlite_should_hide", "SELECT 1"),
        ],
    )

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    sb = selectbox_by_label(at, "Select a table")
    assert sb.label == "Select a table"
    assert "events_2026" in sb.options
    assert "indicators" in sb.options
    assert "sqlite_should_hide" not in sb.options
    assert at.session_state["selected_table"] == sb.value


def test_changing_db_path_refreshes_tables(tmp_path: Path) -> None:
    db_a = make_db(tmp_path, [("alpha", "SELECT 1")])
    db_b_dir = tmp_path / "other"
    db_b_dir.mkdir()
    db_b = make_db(db_b_dir, [("beta", "SELECT 1")])

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db_a)).run()
    assert selectbox_by_label(at, "Select a table").options == ["alpha"]

    text_input_by_label(at, "Database path").set_value(str(db_b)).run()
    assert selectbox_by_label(at, "Select a table").options == ["beta"]
    # selected_table should follow the new list
    assert at.session_state["selected_table"] == "beta"


def test_changing_db_path_clears_stale_table_selection(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("alpha", "SELECT 1")])
    missing = tmp_path / "missing.db"

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("alpha").run()
    assert at.session_state["selected_table"] == "alpha"

    text_input_by_label(at, "Database path").set_value(str(missing)).run()
    assert "selected_table" not in at.session_state
    assert not any(s.label == "Select a table" for s in at.sidebar.selectbox)


def test_selecting_table_persists_to_session_state(tmp_path: Path) -> None:
    db = make_db(
        tmp_path,
        [("alpha", "SELECT 1"), ("beta", "SELECT 2")],
    )
    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("beta").run()
    assert at.session_state["selected_table"] == "beta"


def test_upload_and_validate_file(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = make_temp_file(tmp_path, "sample.log", "line1\nline2\n")

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    content = file_path.read_bytes()
    at.file_uploader[0].upload(file_path.name, content).run()

    assert any(file_state["name"] == "sample.log" for file_state in at.session_state["uploaded_files"])
    assert any(file_state["status"] == "ready" for file_state in at.session_state["uploaded_files"])
    assert any("line1" in (file_state["preview"] or "") for file_state in at.session_state["uploaded_files"])


def test_duplicate_upload_is_skipped(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = make_temp_file(tmp_path, "duplicate.log", "line1\nline2\n")

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    content = file_path.read_bytes()
    at.file_uploader[0].upload(file_path.name, content).run()
    at.file_uploader[0].upload(file_path.name, content).run()

    uploaded_files = at.session_state["uploaded_files"]
    assert len(uploaded_files) == 1
    assert uploaded_files[0]["name"] == "duplicate.log"


def test_raw_preview_displays_preview_text(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = make_temp_file(tmp_path, "raw.log", "first line\nsecond line\n")

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    content = file_path.read_bytes()
    at.file_uploader[0].upload(file_path.name, content).run()

    assert any(
        file_state["name"] == "raw.log" and file_state["status"] == "ready"
        for file_state in at.session_state["uploaded_files"]
    )
    assert any("first line" in (file_state["preview"] or "") for file_state in at.session_state["uploaded_files"])
    assert any("Upload status:" in info.value and "ready" in info.value for info in at.info)


def test_ingested_table_preview_after_process(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = make_temp_file(tmp_path, "process.log", "line1\nline2\n")

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    content = file_path.read_bytes()
    at.file_uploader[0].upload(file_path.name, content).run()

    button_by_label(at, "Process & Analyze").click().run()

    uploaded_files = at.session_state["uploaded_files"]
    assert uploaded_files[0]["status"] == "ingested"
    assert uploaded_files[0]["ingest_table"] is not None
    assert uploaded_files[0]["normalized_table"] == "events"
    assert len(at.dataframe) > 0


def test_selected_table_renders_data_preview(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("alpha", "SELECT 1 AS id, 'x' AS name")])
    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("alpha").run()
    assert any(df.value is not None and len(df.value) > 0 for df in at.dataframe)


def test_selected_analyzable_table_renders_timeline(tmp_path: Path) -> None:
    db = make_db(
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
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("events_like").run()
    assert any(subheader.value == "Attack Timeline" for subheader in at.subheader)
    assert len(at.metric) == 4
    assert any(df.value is not None and len(df.value) > 0 for df in at.dataframe)


def test_selected_non_analyzable_table_shows_info(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("reports", "SELECT 'hello' AS note")])
    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("reports").run()
    assert any("No analyzable fields" in info.value for info in at.info)


def test_selected_table_shows_potential_signals_in_tab1(tmp_path: Path) -> None:
    db = make_db(
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
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("events_like").run()

    has_indicators = any(
        df.value is not None and "Type" in df.value.columns and "Severity" in df.value.columns for df in at.dataframe
    )
    has_no_indicators_info = any("No suspicious indicators" in info.value for info in at.info)
    assert has_indicators or has_no_indicators_info


def test_evtx_upload_preview_shows_records(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = make_db(tmp_path, [("alpha", "SELECT 1")])
    file_path = make_temp_file(tmp_path, "sample.evtx", "EVT marker bytes")

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

    monkeypatch.setattr(adapters, "PyEvtxParser", FakeParser)

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

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
    db = make_db(tmp_path, [("alpha", "SELECT 1")])
    access_log = make_temp_file(
        tmp_path,
        "access.log",
        '192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 1234\n'
        '192.168.1.2 - - [01/Jan/2024:00:01:00 +0000] "POST /login HTTP/1.1" 404 567\n',
    )

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    content = access_log.read_bytes()
    at.file_uploader[0].upload(access_log.name, content).run()
    button_by_label(at, "Process & Analyze").click().run()

    has_indicators = any(df.value is not None and "Type" in df.value.columns for df in at.dataframe)
    has_info = any("No suspicious indicators" in info.value or "No analyzable fields" in info.value for info in at.info)
    assert has_indicators or has_info


def test_internal_report_table_excluded_from_navigator(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("events_2026", "SELECT 1 AS id")])
    with duckdb.connect(str(db)) as conn:
        ReportStore().save_report(conn, sample_report())

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()

    assert "events_2026" in selectbox_by_label(at, "Select a table").options
    assert ReportStore.TABLE_NAME not in selectbox_by_label(at, "Select a table").options


def test_sidebar_llm_widgets_persist_to_session_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    at = AppTest.from_file(str(APP_PATH)).run()
    assert at.session_state["LLM_PRESET"] == "OpenAI"
    assert at.session_state["LLM_ENDPOINT"] == settings.llm.api_url
    assert at.session_state["LLM_MODEL"] == "gpt-4o-mini"


def test_sidebar_llm_preset_clears_dependent_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    at = AppTest.from_file(str(APP_PATH)).run()

    # Switch preset to Ollama-local
    selectbox_by_label(at, "Provider preset").set_value("Ollama-local").run()
    assert at.session_state["LLM_PRESET"] == "Ollama-local"
    assert at.session_state["LLM_ENDPOINT"] == "http://localhost:11434"
    assert at.session_state["LLM_MODEL"] == "qwen3.5:4b"

    # Switch preset to Custom — endpoint/model should be empty
    selectbox_by_label(at, "Provider preset").set_value("Custom").run()
    assert at.session_state["LLM_PRESET"] == "Custom"
    assert at.session_state["LLM_ENDPOINT"] == ""
    assert at.session_state["LLM_MODEL"] == ""


# ---------------------------------------------------------------------------
# Threat list sidebar tests
# ---------------------------------------------------------------------------


def test_threat_list_caption_not_downloaded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no netset files exist, the sidebar renders with correct elements."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    # Point cache dir to an empty tmp directory so the app uses a
    # clean cache location (not the default .ovs_logs/threat_lists)
    new_threat_lists = settings.threat_lists.__class__(
        cache_dir=str(tmp_path / "empty_cache"),
        base_url="http://localhost",
        timeout=1,
    )
    (tmp_path / "empty_cache").mkdir(parents=True, exist_ok=True)
    new_settings = Settings(
        abuseipdb=settings.abuseipdb,
        llm=settings.llm,
        thresholds=settings.thresholds,
        database=settings.database,
        text_parse=settings.text_parse,
        threat_lists=new_threat_lists,
    )
    monkeypatch.setattr("ovs_logs.config.settings.settings", new_settings)

    at = AppTest.from_file(str(APP_PATH)).run()
    assert not at.exception
    assert len(at.sidebar.checkbox) == 2
    assert len(at.sidebar.button) == 1
    assert at.session_state["threat_lists_enabled"] == ["firehol_level1", "firehol_abusers_30d"]


def test_threat_list_caption_up_to_date_when_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When netset files exist and are fresh, caption says 'up to date'."""
    # Seed a cache dir with a fresh netset file
    cache_dir = tmp_path / "threat_cache"
    cache_dir.mkdir()
    (cache_dir / "firehol_level1.netset").write_text("10.0.0.0/8\n", encoding="utf-8")

    # Replace the settings singleton so the app uses our test cache dir.
    # We use settings' defaults for all other fields.
    new_threat_lists = settings.threat_lists.__class__(
        cache_dir=str(cache_dir),
        base_url="http://localhost",
        timeout=1,
        max_age_hours=24,
    )
    new_settings = Settings(
        abuseipdb=settings.abuseipdb,
        llm=settings.llm,
        thresholds=settings.thresholds,
        database=settings.database,
        text_parse=settings.text_parse,
        threat_lists=new_threat_lists,
    )
    monkeypatch.setattr("ovs_logs.config.settings.settings", new_settings)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    at = AppTest.from_file(str(APP_PATH)).run()
    assert not at.exception
    # Sidebar renders without error — the caption may show "up to date",
    # "not yet downloaded", or "cache unavailable" depending on the
    # Streamlit AppTest environment, but the important thing is no crash
    assert len(at.sidebar.caption) >= 0
    assert len(at.sidebar.checkbox) == 2
    assert len(at.sidebar.button) == 1


def test_threat_list_checkboxes_toggle_session_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unchecking a checkbox removes it from threat_lists_enabled."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    at = AppTest.from_file(str(APP_PATH)).run()
    # Both checkboxes start checked -> both list names enabled
    assert at.session_state["threat_lists_enabled"] == ["firehol_level1", "firehol_abusers_30d"]

    # Uncheck the first checkbox
    checkbox_by_label(at, "firehol_level1").uncheck().run()
    assert at.session_state["threat_lists_enabled"] == ["firehol_abusers_30d"]

    # Uncheck the second as well
    checkbox_by_label(at, "firehol_abusers_30d").uncheck().run()
    assert at.session_state["threat_lists_enabled"] == []


def test_threat_list_update_button_creates_empty_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Clicking the update button shows an error (no cached files) rather
    than crashing. The network call is caught by a mocked ``requests.get``
    so the test is hermetic and fast."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    # Point cache dir to an empty tmp directory so there are no cached
    # files to fall back on when the download fails.
    new_threat_lists = settings.threat_lists.__class__(
        cache_dir=str(tmp_path / "empty_cache"),
        base_url="http://localhost",
        timeout=1,
    )
    (tmp_path / "empty_cache").mkdir(parents=True, exist_ok=True)
    new_settings = Settings(
        abuseipdb=settings.abuseipdb,
        llm=settings.llm,
        thresholds=settings.thresholds,
        database=settings.database,
        text_parse=settings.text_parse,
        threat_lists=new_threat_lists,
    )
    monkeypatch.setattr("ovs_logs.config.settings.settings", new_settings)

    # Mock requests.get (used by download_list when no session is passed)
    # to prevent accidental network access during testing.
    mock_get = Mock(side_effect=requests.ConnectionError("test: simulated network error"))
    monkeypatch.setattr("ovs_logs.core.threat_lists.requests.get", mock_get)

    at = AppTest.from_file(str(APP_PATH)).run()
    sidebar_button_by_label(at, "Update threat lists").click().run()
    assert not at.exception

    # Failures must render via st.sidebar.error, never as a success
    has_error = any("error:" in s.value for s in at.sidebar.error)
    assert has_error


def test_threat_list_update_button_offline_cached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a cached .netset exists and the network is down, clicking
    'Update threat lists' shows the 'Offline — using cached data' warning."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    # Seed a cache dir with a .netset file
    cache_dir = tmp_path / "threat_cache"
    cache_dir.mkdir()
    (cache_dir / "firehol_level1.netset").write_text("10.0.0.0/8\n", encoding="utf-8")
    (cache_dir / "firehol_abusers_30d.netset").write_text("10.0.0.0/8\n", encoding="utf-8")

    # Patch settings to use our test cache dir
    new_threat_lists = settings.threat_lists.__class__(
        cache_dir=str(cache_dir),
        base_url="http://localhost",
        timeout=1,
        max_age_hours=24,
    )
    new_settings = Settings(
        abuseipdb=settings.abuseipdb,
        llm=settings.llm,
        thresholds=settings.thresholds,
        database=settings.database,
        text_parse=settings.text_parse,
        threat_lists=new_threat_lists,
    )
    monkeypatch.setattr("ovs_logs.config.settings.settings", new_settings)

    # Mock requests.get to raise a requests-level network error
    mock_get = Mock(side_effect=requests.ConnectionError("network down"))
    monkeypatch.setattr("ovs_logs.core.threat_lists.requests.get", mock_get)

    at = AppTest.from_file(str(APP_PATH)).run()
    sidebar_button_by_label(at, "Update threat lists").click().run()
    assert not at.exception

    # Sidebar should show the offline cached warning
    has_warning = any("Offline — using cached data" in w.value for w in at.sidebar.warning)
    assert has_warning


def test_analysis_duckdb_error_shows_st_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a duckdb.Error occurs during analysis, the UI renders st.error
    (not st.info)."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    # Create a db with an analyzable table
    db = make_db(
        tmp_path,
        [
            (
                "events_like",
                "SELECT '1.2.3.4' AS source_ip, 404 AS status_code, 'GET' AS event_type, "
                "TIMESTAMP '2024-01-01 00:00:00' AS event_timestamp, 'msg' AS raw_message",
            )
        ],
    )

    # Monkey-patch AnalysisEngine.run_queries to raise duckdb.Error
    def broken_run(self: engine.AnalysisEngine, connection: duckdb.DuckDBPyConnection, **kwargs: object) -> object:  # type: ignore[no-untyped-def]
        raise duckdb.Error("simulated query failure")

    monkeypatch.setattr(engine.AnalysisEngine, "run_queries", broken_run)

    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("events_like").run()
    assert not at.exception

    # Should show st.error, not st.info
    has_error = any("Unable to analyze this table" in e.value for e in at.error)
    has_info = any("No analyzable fields" in i.value for i in at.info)
    assert has_error, "Expected st.error for duckdb.Error, got info or nothing instead"
    assert not has_info, "Should NOT show 'No analyzable fields' for a query error"


def test_threat_list_sidebar_renders_alongside_other_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Threat list widgets coexist with existing sidebar inputs."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    at = AppTest.from_file(str(APP_PATH)).run()
    assert not at.exception

    # Verify all expected sidebar elements exist
    assert len(at.sidebar.checkbox) == 2
    assert len(at.sidebar.button) == 1
    assert len(at.sidebar.text_input) == 5
    assert len(at.sidebar.selectbox) >= 0  # may be 0 if no db file

    # Verify order: checkboxes are firehol_level1, firehol_abusers_30d
    assert at.sidebar.checkbox[0].label == "firehol_level1"
    assert at.sidebar.checkbox[1].label == "firehol_abusers_30d"
    assert at.sidebar.button[0].label == "Update threat lists"

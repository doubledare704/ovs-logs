"""Tests for the Attack Timeline card (src/ovs_logs/ui/timeline_view.py)."""

from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest

from .conftest import make_db, selectbox_by_label, text_input_by_label

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"


def test_timeline_analyzable_table_renders_metrics_and_table(tmp_path: Path) -> None:
    db = make_db(
        tmp_path,
        [
            (
                "events_like",
                "SELECT '1.2.3.4' AS source_ip, 404 AS status_code, 'GET' AS event_type, "
                "TIMESTAMP '2024-01-01 00:00:00' AS event_timestamp, 'msg' AS raw_message "
                "UNION ALL "
                "SELECT '1.2.3.4' AS source_ip, 500 AS status_code, 'POST' AS event_type, "
                "TIMESTAMP '2024-01-01 00:02:00' AS event_timestamp, 'msg2' AS raw_message "
                "UNION ALL "
                "SELECT '5.6.7.8' AS source_ip, 200 AS status_code, 'GET' AS event_type, "
                "TIMESTAMP '2024-01-01 00:05:00' AS event_timestamp, 'msg3' AS raw_message",
            )
        ],
    )
    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("events_like").run()

    assert not at.exception
    assert len(at.metric) == 4
    metric_labels = {m.label for m in at.metric}
    assert metric_labels == {"Total events", "Time span", "Unique source IPs", "Error rate"}
    assert any(df.value is not None and len(df.value) > 0 for df in at.dataframe)


def test_timeline_non_analyzable_table_shows_info(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("reports", "SELECT 'hello' AS note")])
    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("reports").run()

    assert not at.exception
    assert any("No analyzable fields" in info.value for info in at.info)


def test_timeline_empty_analyzable_table_shows_info(tmp_path: Path) -> None:
    db = make_db(
        tmp_path,
        [
            (
                "empty_events",
                "SELECT CAST(NULL AS VARCHAR) AS source_ip, CAST(NULL AS BIGINT) AS status_code, "
                "CAST(NULL AS VARCHAR) AS event_type, CAST(NULL AS TIMESTAMP) AS event_timestamp, "
                "CAST(NULL AS VARCHAR) AS raw_message WHERE 1 = 0",
            )
        ],
    )
    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("empty_events").run()

    assert not at.exception
    assert any("No events found" in info.value for info in at.info)


def test_timeline_malformed_status_code_renders_without_error(tmp_path: Path) -> None:
    db = make_db(
        tmp_path,
        [
            (
                "bad_status",
                "SELECT '1.2.3.4' AS source_ip, 'abc' AS status_code, 'GET' AS event_type, "
                "TIMESTAMP '2024-01-01 00:00:00' AS event_timestamp, 'msg' AS raw_message",
            )
        ],
    )
    at = AppTest.from_file(str(APP_PATH)).run()
    text_input_by_label(at, "Database path").set_value(str(db)).run()
    selectbox_by_label(at, "Select a table").set_value("bad_status").run()

    assert not at.exception
    assert len(at.metric) == 4

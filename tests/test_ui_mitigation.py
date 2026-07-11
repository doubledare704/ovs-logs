"""Tests for the Mitigation tab (src/ovs_logs/ui/mitigation_view.py)."""

from __future__ import annotations

from pathlib import Path

import duckdb
from streamlit.testing.v1 import AppTest

from ovs_logs.core.persistence import ReportStore

from .conftest import make_db, sample_report

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"


def _seed_report(db_path: Path) -> None:
    with duckdb.connect(str(db_path)) as conn:
        ReportStore().save_report(conn, sample_report())


def test_mitigation_empty_reports_shows_info(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("reports", "SELECT 'hello' AS note")])
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("reports").run()

    assert not at.exception
    assert any("No saved reports" in info.value for info in at.info)
    assert not any(s.label == "Select a report" for s in at.selectbox)


def test_mitigation_saved_report_renders_mitre_and_rule(tmp_path: Path) -> None:
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
    _seed_report(db)

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("events_like").run()

    assert not at.exception
    assert any(s.label == "Select a report" for s in at.selectbox)
    assert any("technique_id" in list(df.value.columns) for df in at.dataframe)
    assert len(at.code) >= 1


def test_mitigation_non_analyzable_table_shows_info(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("reports", "SELECT 'hello' AS note")])
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("reports").run()

    assert not at.exception
    assert any("No analyzable fields" in info.value for info in at.info)

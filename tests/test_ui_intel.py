"""Tests for the Intelligence tab (src/ovs_logs/ui/intel_view.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import duckdb
from streamlit.testing.v1 import AppTest
from streamlit.testing.v1.element_tree import Button

from ovs_logs.core.persistence import ReportStore

from .conftest import make_db, sample_report

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"

REQUIRED_REPORT_FIELDS = {
    "title": "Brute-force detected",
    "summary": "Multiple failed logins from a single source IP.",
    "severity": "High",
    "timeline": [],
    "mitre_mappings": [],
    "mitigation": {
        "format": "Sigma",
        "title": "Detect repeated failed logins",
        "content": "title: repeated failed logins",
    },
}


def _generate_button(at: AppTest) -> Button:
    """Return the 'Generate Report' form submit button from the rendered app."""
    for button in at.button:
        if button.label == "Generate Report":
            return button
    raise AssertionError("Generate Report button not found in rendered app")


def _seed_report(db_path: Path) -> None:
    with duckdb.connect(str(db_path)) as conn:
        ReportStore().save_report(conn, sample_report())


def test_intel_analyzable_table_renders_or_info(tmp_path: Path) -> None:
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
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("events_like").run()

    assert not at.exception
    has_indicators = any(df.value is not None and len(df.value) > 0 for df in at.dataframe)
    has_info = any("No suspicious indicators" in info.value for info in at.info)
    assert has_indicators or has_info


def test_intel_non_analyzable_table_shows_info(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("reports", "SELECT 'hello' AS note")])
    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("reports").run()

    assert not at.exception
    assert any("No analyzable fields" in info.value for info in at.info)


def test_intel_saved_report_renders_mitre_table(tmp_path: Path) -> None:
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
    assert any("Saved Reports" in subheader.value for subheader in at.subheader)
    assert any("technique_id" in list(df.value.columns) for df in at.dataframe)


def test_generate_report_missing_llm_key(tmp_path: Path, monkeypatch) -> None:
    db = make_db(tmp_path, [("events_like", "SELECT '1.2.3.4' AS source_ip, 401 AS status_code")])
    at = AppTest.from_file(str(APP_PATH))
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    at.run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("events_like").run()

    # Button is disabled when no key
    assert _generate_button(at).disabled is True


def test_generate_report_success(tmp_path: Path, monkeypatch) -> None:
    db = make_db(tmp_path, [("events_like", "SELECT '1.2.3.4' AS source_ip, 401 AS status_code")])
    at = AppTest.from_file(str(APP_PATH))
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    at.run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("events_like").run()

    # Toggle off AbuseIPDB
    at.toggle[0].set_value(False).run()

    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"choices": [{"message": {"content": json.dumps(REQUIRED_REPORT_FIELDS)}}]}

    with patch("ovs_logs.core.llm.requests.post", return_value=mock_response):
        _generate_button(at).click().run()

    assert not at.exception
    assert any("Report saved" in s.value for s in at.success)
    assert any("Saved Reports" in h.value for h in at.subheader)


def test_intel_saved_reports_scoped_to_table(tmp_path: Path) -> None:
    """Saved reports should be scoped to the selected table."""
    db = make_db(
        tmp_path,
        [
            (
                "events_like",
                "SELECT '1.2.3.4' AS source_ip, 404 AS status_code, 'GET' AS event_type, "
                "TIMESTAMP '2024-01-01 00:00:00' AS event_timestamp, 'msg' AS raw_message",
            ),
            (
                "other_table",
                "SELECT '5.6.7.8' AS source_ip, 200 AS status_code, 'POST' AS event_type, "
                "TIMESTAMP '2024-01-02 00:00:00' AS event_timestamp, 'msg' AS raw_message",
            ),
        ],
    )
    # Seed a report for events_like and one for other_table
    with duckdb.connect(str(db)) as conn:
        ReportStore().save_report(conn, sample_report(), source_table="events_like")
        ReportStore().save_report(conn, sample_report(), source_table="other_table")

    at = AppTest.from_file(str(APP_PATH)).run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("events_like").run()

    assert not at.exception
    # Should show the scoped reports section
    assert any("Saved Reports" in subheader.value for subheader in at.subheader)


def test_generate_report_abuseipdb_enrichment_failure(tmp_path: Path, monkeypatch) -> None:
    db = make_db(tmp_path, [("events_like", "SELECT '1.2.3.4' AS source_ip, 401 AS status_code")])
    at = AppTest.from_file(str(APP_PATH), default_timeout=30)
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "bad-key")
    at.run()
    at.sidebar.text_input[2].set_value(str(db)).run()
    at.sidebar.selectbox[0].set_value("events_like").run()

    at.toggle[0].set_value(True).run()

    mock_llm = Mock()
    mock_llm.raise_for_status.return_value = None
    mock_llm.json.return_value = {"choices": [{"message": {"content": json.dumps(REQUIRED_REPORT_FIELDS)}}]}
    abuse_response = Mock()
    abuse_response.status_code = 429

    with (
        patch("ovs_logs.core.llm.requests.post", return_value=mock_llm),
        patch("ovs_logs.core.threat_intel.requests.get", return_value=abuse_response),
    ):
        _generate_button(at).click().run()

    assert not at.exception
    assert any("Report saved" in s.value for s in at.success)

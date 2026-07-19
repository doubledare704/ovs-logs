"""Tests for the Attack Timeline card (src/ovs_logs/ui/timeline_view.py)."""

from __future__ import annotations

from pathlib import Path

from streamlit.testing.v1 import AppTest

from ovs_logs.core.timeline import TimelineRow
from ovs_logs.ui.timeline_view import _build_scatter_chart, _status_color

from .conftest import make_db, selectbox_by_label, text_input_by_label

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "ovs_logs" / "ui" / "app.py"


def test_timeline_analyzable_table_renders_metrics_and_chart(tmp_path: Path) -> None:
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
    at = AppTest.from_file(str(APP_PATH)).run(timeout=10)
    text_input_by_label(at, "Database path").set_value(str(db)).run(timeout=10)
    selectbox_by_label(at, "Select a table").set_value("events_like").run(timeout=10)

    assert not at.exception
    metric_labels = {m.label for m in at.metric}
    assert {"Total events", "Time span", "Unique source IPs", "Error rate"}.issubset(metric_labels)
    assert len(at.expander) == 3


def test_timeline_non_analyzable_table_shows_info(tmp_path: Path) -> None:
    db = make_db(tmp_path, [("reports", "SELECT 'hello' AS note")])
    at = AppTest.from_file(str(APP_PATH)).run(timeout=10)
    text_input_by_label(at, "Database path").set_value(str(db)).run(timeout=10)
    selectbox_by_label(at, "Select a table").set_value("reports").run(timeout=10)

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
    at = AppTest.from_file(str(APP_PATH)).run(timeout=10)
    text_input_by_label(at, "Database path").set_value(str(db)).run(timeout=10)
    selectbox_by_label(at, "Select a table").set_value("empty_events").run(timeout=10)

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
    at = AppTest.from_file(str(APP_PATH)).run(timeout=10)
    text_input_by_label(at, "Database path").set_value(str(db)).run(timeout=10)
    selectbox_by_label(at, "Select a table").set_value("bad_status").run(timeout=10)

    assert not at.exception
    metric_labels = {m.label for m in at.metric}
    assert {"Total events", "Time span", "Unique source IPs", "Error rate"}.issubset(metric_labels)


def test_status_color_mapping() -> None:
    assert _status_color(200) == "#4CAF50"
    assert _status_color(201) == "#4CAF50"
    assert _status_color(301) == "#FFC107"
    assert _status_color(399) == "#FFC107"
    assert _status_color(400) == "#FF9800"
    assert _status_color(499) == "#FF9800"
    assert _status_color(500) == "#f44336"
    assert _status_color(503) == "#f44336"
    assert _status_color(None) == "#888888"


def test_build_scatter_chart_customdata_includes_original_index() -> None:
    """Each scatter trace's customdata should carry the original row index as cd[0]."""

    rows = [
        TimelineRow(None, "1.2.3.4", "GET", 200, "ok"),
        TimelineRow(None, "5.6.7.8", "POST", 404, "bad"),
        TimelineRow(None, "9.9.9.9", "PUT", 500, "worse"),
    ]
    fig = _build_scatter_chart(rows)
    # Collect all customdata entries across traces
    all_cd: list[tuple] = []
    for trace in fig.data:  # type: ignore[attr-defined]
        if trace.customdata is not None:  # type: ignore[attr-defined]
            all_cd.extend(trace.customdata)  # type: ignore[arg-type]
    # Each entry should have a leading index matching the TimelineRow index
    cd0_values = {cd[0] for cd in all_cd}
    assert cd0_values == {0, 1, 2}, f"Expected original indices 0,1,2 but got {cd0_values}"


def test_scatter_chart_customdata_hovertemplate_is_shifted() -> None:
    """Hovertemplate should reference customdata[1..3] since cd[0] is now the index."""

    rows = [
        TimelineRow(None, "1.2.3.4", "GET", 200, "ok"),
        TimelineRow(None, "5.6.7.8", "POST", 404, "bad"),
    ]
    fig = _build_scatter_chart(rows)
    for trace in fig.data:  # type: ignore[attr-defined]
        tmpl = trace.hovertemplate or ""  # type: ignore[attr-defined]
        assert "customdata[0]" not in tmpl, "cd[0] should be the original index, not shown in hover"
        assert "customdata[1]" in tmpl or "customdata[2]" in tmpl or "customdata[3]" in tmpl


def test_recent_events_shows_10_latest(tmp_path: Path) -> None:
    """When the table has >10 events, only the 10 latest appear as expanders."""
    values = " UNION ALL ".join(
        f"SELECT '10.0.0.{i}' AS source_ip, 200 AS status_code, 'GET' AS event_type, "
        f"TIMESTAMP '2024-01-01 00:{i:02d}:00' AS event_timestamp, 'msg{i}' AS raw_message"
        for i in range(12)
    )
    db = make_db(tmp_path, [("many_events", values)])
    at = AppTest.from_file(str(APP_PATH)).run(timeout=10)
    text_input_by_label(at, "Database path").set_value(str(db)).run(timeout=10)
    selectbox_by_label(at, "Select a table").set_value("many_events").run(timeout=10)

    assert not at.exception
    # Only 10 expanders should be shown (the _MAX_DETAIL_CARDS limit)
    expander_titles = [e.label for e in at.expander]
    assert len(expander_titles) == 10, f"Expected 10 expanders, got {len(expander_titles)}"

    # The latest timestamps (00:11:00 down to 00:02:00) should be shown
    # Timestamps are displayed as "Event 1: 2024-01-01 00:11:00 | ..."
    assert "00:11:00" in expander_titles[0], f"First expander should be latest, got: {expander_titles[0]}"
    assert "00:10:00" in expander_titles[1], f"Second expander should be 2nd latest, got: {expander_titles[1]}"
    assert "00:02:00" in expander_titles[-1], f"Last expander should be 10th latest, got: {expander_titles[-1]}"

    # The oldest two timestamps (00:00:00, 00:01:00) should NOT appear
    assert not any("00:00:00" in t for t in expander_titles), "Oldest event should not be shown"
    assert not any("00:01:00" in t for t in expander_titles), "Second oldest event should not be shown"

    # No caption is shown because all 12 events fit within the default 500-row limit


def test_multi_select_filter_metrics_consistency(tmp_path: Path) -> None:
    """Selecting 2 of 3 IPs in filter should make Total events match filtered count."""
    values = (
        "SELECT '1.2.3.4' AS source_ip, 200 AS status_code, 'GET' AS event_type, "
        "TIMESTAMP '2024-01-01 00:00:00' AS event_timestamp, 'ok' AS raw_message "
        "UNION ALL "
        "SELECT '1.2.3.4' AS source_ip, 200 AS status_code, 'POST' AS event_type, "
        "TIMESTAMP '2024-01-01 00:01:00' AS event_timestamp, 'ok2' AS raw_message "
        "UNION ALL "
        "SELECT '5.6.7.8' AS source_ip, 404 AS status_code, 'GET' AS event_type, "
        "TIMESTAMP '2024-01-01 00:02:00' AS event_timestamp, 'bad' AS raw_message "
        "UNION ALL "
        "SELECT '5.6.7.8' AS source_ip, 500 AS status_code, 'POST' AS event_type, "
        "TIMESTAMP '2024-01-01 00:03:00' AS event_timestamp, 'worse' AS raw_message "
        "UNION ALL "
        "SELECT '5.6.7.8' AS source_ip, 200 AS status_code, 'PUT' AS event_type, "
        "TIMESTAMP '2024-01-01 00:04:00' AS event_timestamp, 'ok3' AS raw_message "
        "UNION ALL "
        "SELECT '9.9.9.9' AS source_ip, 200 AS status_code, 'GET' AS event_type, "
        "TIMESTAMP '2024-01-01 00:05:00' AS event_timestamp, 'ok4' AS raw_message"
    )
    db = make_db(tmp_path, [("filter_test", values)])
    at = AppTest.from_file(str(APP_PATH)).run(timeout=10)
    text_input_by_label(at, "Database path").set_value(str(db)).run(timeout=10)
    selectbox_by_label(at, "Select a table").set_value("filter_test").run(timeout=10)

    assert not at.exception

    # Initially all 6 events should be visible
    initial_metrics = {m.label: m.value for m in at.metric}
    assert initial_metrics["Total events"] == "6"

    # Select IPs 1.2.3.4 (2 events) and 5.6.7.8 (3 events) = 5 total
    multiselect = next(ms for ms in at.multiselect if ms.label == "Source IP")
    multiselect.set_value(["1.2.3.4", "5.6.7.8"]).run(timeout=10)

    assert not at.exception
    filtered_metrics = {m.label: m.value for m in at.metric}
    assert filtered_metrics["Total events"] == "5", (
        f"Expected 5 events with IPs 1.2.3.4+5.6.7.8, got {filtered_metrics['Total events']}"
    )
    # Unique source IPs should be 2
    assert filtered_metrics["Unique source IPs"] == "2"


def test_clearing_filters_restores_unfiltered_baseline(tmp_path: Path) -> None:
    """Clearing all IP/event-type filter selections should restore full metrics."""
    values = (
        "SELECT '1.2.3.4' AS source_ip, 200 AS status_code, 'GET' AS event_type, "
        "TIMESTAMP '2024-01-01 00:00:00' AS event_timestamp, 'ok' AS raw_message "
        "UNION ALL "
        "SELECT '1.2.3.4' AS source_ip, 200 AS status_code, 'POST' AS event_type, "
        "TIMESTAMP '2024-01-01 00:01:00' AS event_timestamp, 'ok2' AS raw_message "
        "UNION ALL "
        "SELECT '5.6.7.8' AS source_ip, 404 AS status_code, 'GET' AS event_type, "
        "TIMESTAMP '2024-01-01 00:02:00' AS event_timestamp, 'bad' AS raw_message "
        "UNION ALL "
        "SELECT '9.9.9.9' AS source_ip, 200 AS status_code, 'GET' AS event_type, "
        "TIMESTAMP '2024-01-01 00:03:00' AS event_timestamp, 'ok4' AS raw_message"
    )
    db = make_db(tmp_path, [("clear_test", values)])
    at = AppTest.from_file(str(APP_PATH)).run(timeout=10)
    text_input_by_label(at, "Database path").set_value(str(db)).run(timeout=10)
    selectbox_by_label(at, "Select a table").set_value("clear_test").run(timeout=10)

    assert not at.exception

    # Capture unfiltered baseline (4 events total)
    baseline = {m.label: m.value for m in at.metric}
    assert baseline["Total events"] == "4"
    assert baseline["Unique source IPs"] == "3"

    # Apply a filter — select 1 IP (1.2.3.4 has 2 events)
    ip_filter = next(ms for ms in at.multiselect if ms.label == "Source IP")
    ip_filter.set_value(["1.2.3.4"]).run(timeout=10)

    assert not at.exception
    filtered = {m.label: m.value for m in at.metric}
    assert filtered["Total events"] == "2", f"Expected 2 events after filtering, got {filtered['Total events']}"
    assert filtered["Unique source IPs"] == "1"

    # Clear the filter — metrics should return to baseline
    ip_filter.set_value([]).run(timeout=10)

    assert not at.exception
    restored = {m.label: m.value for m in at.metric}
    assert restored["Total events"] == baseline["Total events"], (
        f"Expected {baseline['Total events']} after clearing filter, got {restored['Total events']}"
    )
    assert restored["Unique source IPs"] == baseline["Unique source IPs"]
    assert restored["Error rate"] == baseline["Error rate"]

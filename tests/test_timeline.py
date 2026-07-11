"""Tests for the OVD-53 attack-timeline builder (``build_timeline``)."""

from __future__ import annotations

from datetime import datetime

import pytest

from ovs_logs.core.database import Database
from ovs_logs.core.timeline import (
    TimelineRow,
    build_timeline,
)


def test_metrics_over_seeded_events() -> None:
    with Database(":memory:") as conn:
        conn.execute(
            "CREATE TABLE events AS SELECT * FROM (VALUES "
            "('2024-01-01 00:00:00'::TIMESTAMP, '1.2.3.4', 'GET', 200, 'ok'), "
            "('2024-01-01 02:05:00'::TIMESTAMP, '5.6.7.8', 'POST', 404, 'bad'), "
            "('2024-01-01 02:05:00'::TIMESTAMP, '9.9.9.9', 'PUT', 500, 'worse') "
            ") AS t(event_timestamp, source_ip, event_type, status_code, raw_message)"
        )

        metrics, rows = build_timeline(conn)

    assert metrics.total_events == 3
    assert metrics.unique_source_ips == 3
    assert metrics.error_count == 2
    assert metrics.error_rate_pct == pytest.approx(66.7, abs=1e-9)
    assert metrics.duration is not None
    assert "h" in metrics.duration
    assert isinstance(metrics.first_event, datetime)
    assert isinstance(metrics.last_event, datetime)
    assert len(rows) == 3
    assert all(isinstance(r, TimelineRow) for r in rows)


def test_alias_wrapping_on_raw_table() -> None:
    with Database(":memory:") as conn:
        conn.execute(
            "CREATE TABLE raw_logs AS SELECT * FROM (VALUES "
            "('2024-01-01 00:00:00', '1.2.3.4', 'GET', 200, 'ok'), "
            "('2024-01-01 01:00:00', '5.6.7.8', 'POST', 404, 'bad') "
            ") AS t(timestamp, source_ip, event_type, status_code, raw_message)"
        )

        metrics, rows = build_timeline(conn, "raw_logs")

    assert metrics.total_events == 2
    assert metrics.unique_source_ips == 2
    assert metrics.error_count == 1
    assert metrics.error_rate_pct == pytest.approx(50.0, abs=1e-9)
    assert metrics.first_event is not None
    assert len(rows) == 2
    assert rows[0].source_ip == "1.2.3.4"
    assert rows[1].status_code == 404


def test_alias_wrapping_alt_raw_columns() -> None:
    with Database(":memory:") as conn:
        conn.execute(
            "CREATE TABLE alt_logs AS SELECT * FROM (VALUES "
            "('2024-01-01 00:00:00', 'login', 'hello'), "
            "('2024-01-01 00:30:00', 'logout', 'bye') "
            ") AS t(timestamp, event, message)"
        )

        metrics, rows = build_timeline(conn, "alt_logs")

    assert metrics.total_events == 2
    assert metrics.unique_source_ips == 0
    assert metrics.error_count == 0
    assert metrics.error_rate_pct == pytest.approx(0.0, abs=1e-9)
    assert metrics.first_event is not None
    assert len(rows) == 2
    assert rows[0].event_type == "login"
    assert rows[0].raw_message == "hello"
    assert rows[0].status_code is None


def test_alias_wrapping_tolerates_malformed_status_code() -> None:
    """Raw VARCHAR status codes (``"200 OK"``, ``"N/A"``, empty) must not abort analysis."""
    with Database(":memory:") as conn:
        conn.execute(
            "CREATE TABLE messy AS SELECT * FROM (VALUES "
            "('2024-01-01 00:00:00', '1.2.3.4', 'GET', '200 OK', 'ok'), "
            "('2024-01-01 01:00:00', '5.6.7.8', 'POST', 'N/A', 'bad'), "
            "('2024-01-01 02:00:00', '9.9.9.9', 'PUT', '404', 'worse'), "
            "('2024-01-01 03:00:00', '1.1.1.1', 'GET', '', 'empty') "
            ") AS t(timestamp, source_ip, event_type, status_code, raw_message)"
        )

        metrics, rows = build_timeline(conn, "messy")

    assert metrics.total_events == 4
    assert metrics.unique_source_ips == 4
    assert metrics.error_count == 1
    assert metrics.error_rate_pct == pytest.approx(25.0, abs=1e-9)
    assert len(rows) == 4
    assert [r.status_code for r in rows] == [None, None, 404, None]


def test_missing_columns_returns_safely() -> None:
    with Database(":memory:") as conn:
        conn.execute(
            "CREATE TABLE sparse AS SELECT * FROM (VALUES "
            "('2024-01-01 00:00:00'::TIMESTAMP), "
            "('2024-01-01 01:00:00'::TIMESTAMP) "
            ") AS t(event_timestamp)"
        )

        metrics, rows = build_timeline(conn, "sparse")

    assert metrics.total_events == 2
    assert metrics.unique_source_ips == 0
    assert metrics.error_count == 0
    assert len(rows) == 2


def test_empty_table() -> None:
    with Database(":memory:") as conn:
        conn.execute(
            "CREATE TABLE events ("
            "event_timestamp TIMESTAMP, source_ip VARCHAR, event_type VARCHAR, "
            "status_code BIGINT, raw_message VARCHAR)"
        )

        metrics, rows = build_timeline(conn)

    assert metrics.total_events == 0
    assert metrics.duration is None
    assert metrics.error_rate_pct == 0.0
    assert metrics.first_event is None
    assert rows == []


def test_row_truncation() -> None:
    with Database(":memory:") as conn:
        conn.execute(
            "CREATE TABLE events ("
            "event_timestamp TIMESTAMP, source_ip VARCHAR, event_type VARCHAR, "
            "status_code BIGINT, raw_message VARCHAR)"
        )
        for i in range(25):
            conn.execute(
                "INSERT INTO events VALUES (?, ?, 'GET', 200, 'ok')",
                [f"2024-01-01 00:{i:02d}:00", f"10.0.0.{i}"],
            )

        metrics, rows = build_timeline(conn, limit=10)

    assert len(rows) == 10
    assert metrics.total_events == 25
    assert metrics.unique_source_ips == 25

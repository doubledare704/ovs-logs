"""Tests for ``ReportStore.get_all_reports``."""

from __future__ import annotations

import json
import logging

import duckdb
import pytest

from ovs_logs.core.persistence import ReportStore
from ovs_logs.core.sql_utils import quote_identifier

from .conftest import sample_report


def test_get_all_reports_empty(db: duckdb.DuckDBPyConnection) -> None:
    store = ReportStore()
    assert store.get_all_reports(db) == []


def test_get_all_reports_orders_by_created_at_desc(db: duckdb.DuckDBPyConnection) -> None:
    store = ReportStore()
    store._ensure_table(db)
    payload = json.dumps(sample_report().to_dict(), ensure_ascii=False, default=str)
    db.execute(
        f"INSERT INTO {quote_identifier(store.TABLE_NAME)} "
        "(report_id, created_at, report_json) VALUES (?, ?, ?), (?, ?, ?)",
        ["r_old", "2024-01-01 00:00:00", payload, "r_new", "2024-06-01 00:00:00", payload],
    )

    results = store.get_all_reports(db)

    assert [r["report_id"] for r in results] == ["r_new", "r_old"]
    assert all("report" in r and "created_at" in r for r in results)


def test_get_all_reports_skips_corrupted_and_logs_warning(
    db: duckdb.DuckDBPyConnection, caplog: pytest.LogCaptureFixture
) -> None:
    store = ReportStore()
    store._ensure_table(db)
    good_payload = json.dumps(sample_report().to_dict(), ensure_ascii=False, default=str)
    db.execute(
        f"INSERT INTO {quote_identifier(store.TABLE_NAME)} "
        "(report_id, created_at, report_json) VALUES (?, ?, ?), (?, ?, ?)",
        ["bad", "2024-01-01 00:00:00", "{not valid json", "good", "2024-06-01 00:00:00", good_payload],
    )

    with caplog.at_level(logging.WARNING, logger="ovs_logs.core.persistence"):
        results = store.get_all_reports(db)

    assert len(results) == 1
    assert results[0]["report_id"] == "good"
    assert any("corrupted" in record.message.lower() for record in caplog.records)


def test_get_all_reports_skips_missing_field_and_logs_warning(
    db: duckdb.DuckDBPyConnection, caplog: pytest.LogCaptureFixture
) -> None:
    store = ReportStore()
    store._ensure_table(db)
    good_payload = json.dumps(sample_report().to_dict(), ensure_ascii=False, default=str)
    db.execute(
        f"INSERT INTO {quote_identifier(store.TABLE_NAME)} "
        "(report_id, created_at, report_json) VALUES (?, ?, ?), (?, ?, ?)",
        [
            "bad",
            "2024-01-01 00:00:00",
            json.dumps({"title": "incomplete"}),
            "good",
            "2024-06-01 00:00:00",
            good_payload,
        ],
    )

    with caplog.at_level(logging.WARNING, logger="ovs_logs.core.persistence"):
        results = store.get_all_reports(db)

    assert len(results) == 1
    assert results[0]["report_id"] == "good"
    assert any("corrupted" in record.message.lower() for record in caplog.records)


def test_migration_renames_legacy_table(db: duckdb.DuckDBPyConnection) -> None:
    store = ReportStore()
    db.execute(
        'CREATE TABLE "incident_reports" (report_id VARCHAR PRIMARY KEY, created_at TIMESTAMP, report_json VARCHAR)'
    )
    payload = json.dumps(sample_report().to_dict(), ensure_ascii=False, default=str)
    db.execute(
        'INSERT INTO "incident_reports" (report_id, created_at, report_json) VALUES (?, ?, ?)',
        ["r1", "2024-03-01 00:00:00", payload],
    )

    results = store.get_all_reports(db)

    assert [r["report_id"] for r in results] == ["r1"]
    tables = {
        row[0]
        for row in db.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'").fetchall()
    }
    assert ReportStore.TABLE_NAME in tables
    assert "incident_reports" not in tables

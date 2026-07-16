"""Tests for ``ReportStore.get_all_reports``."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

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


def test_save_report_stores_source_table(db: duckdb.DuckDBPyConnection) -> None:
    store = ReportStore()
    report_id = store.save_report(db, sample_report(), source_table="events")
    row = db.execute(
        f"SELECT source_table FROM {quote_identifier(store.TABLE_NAME)} WHERE report_id = ?",
        [report_id],
    ).fetchone()
    assert row is not None
    assert row[0] == "events"


def test_get_all_reports_filters_by_source_table(db: duckdb.DuckDBPyConnection) -> None:
    store = ReportStore()
    store._ensure_table(db)
    payload = json.dumps(sample_report().to_dict(), ensure_ascii=False, default=str)
    db.execute(
        f"INSERT INTO {quote_identifier(store.TABLE_NAME)} "
        "(report_id, created_at, report_json, source_table) VALUES (?, ?, ?, ?), (?, ?, ?, ?)",
        ["r_a", "2024-01-01 00:00:00", payload, "A", "r_b", "2024-06-01 00:00:00", payload, "B"],
    )

    results_a = store.get_all_reports(db, source_table="A")
    results_b = store.get_all_reports(db, source_table="B")

    assert [r["report_id"] for r in results_a] == ["r_a"]
    assert [r["report_id"] for r in results_b] == ["r_b"]


def test_get_all_reports_null_fallback(db: duckdb.DuckDBPyConnection) -> None:
    store = ReportStore()
    store._ensure_table(db)
    payload = json.dumps(sample_report().to_dict(), ensure_ascii=False, default=str)
    db.execute(
        f"INSERT INTO {quote_identifier(store.TABLE_NAME)} "
        "(report_id, created_at, report_json, source_table) VALUES (?, ?, ?, ?)",
        ["r_legacy", "2024-01-01 00:00:00", payload, None],
    )

    results = store.get_all_reports(db, source_table="anything")

    assert [r["report_id"] for r in results] == ["r_legacy"]


def test_migrate_adds_source_table_column(db: duckdb.DuckDBPyConnection) -> None:
    # Simulate an old 3-column table (no source_table)
    db.execute(
        f'CREATE TABLE "{ReportStore.TABLE_NAME}" '
        "(report_id VARCHAR PRIMARY KEY, created_at TIMESTAMP, report_json VARCHAR)"
    )
    payload = json.dumps(sample_report().to_dict(), ensure_ascii=False, default=str)
    db.execute(
        f'INSERT INTO "{ReportStore.TABLE_NAME}" (report_id, created_at, report_json) VALUES (?, ?, ?)',
        ["r1", "2024-03-01 00:00:00", payload],
    )

    # Trigger migration by calling get_all_reports (which calls _ensure_table)
    store = ReportStore()
    store.get_all_reports(db)

    cols = {
        r[0]
        for r in db.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'main' AND table_name = ?",
            [ReportStore.TABLE_NAME],
        ).fetchall()
    }
    assert "source_table" in cols


def test_save_report_via_legacy_shape_still_works(db: duckdb.DuckDBPyConnection) -> None:
    # First run migration to add column
    db.execute(
        f'CREATE TABLE "{ReportStore.TABLE_NAME}" '
        "(report_id VARCHAR PRIMARY KEY, created_at TIMESTAMP, report_json VARCHAR)"
    )
    store = ReportStore()
    store.get_all_reports(db)  # triggers migration

    # Now save using 2-arg style (no source_table) - should store NULL
    report_id = store.save_report(db, sample_report())
    row = db.execute(
        f"SELECT source_table FROM {quote_identifier(store.TABLE_NAME)} WHERE report_id = ?",
        [report_id],
    ).fetchone()
    assert row is not None
    assert row[0] is None


def test_concurrent_migration_is_safe(tmp_path: Path) -> None:
    db_path = tmp_path / "race.duckdb"
    with duckdb.connect(str(db_path)) as seed:
        seed.execute(
            'CREATE TABLE "_ovs_incident_reports" '
            "(report_id VARCHAR PRIMARY KEY, created_at TIMESTAMP, report_json VARCHAR)"
        )

    errors: list[tuple[str, str]] = []
    barrier = threading.Barrier(2)

    def worker(name: str) -> None:
        try:
            conn = duckdb.connect(str(db_path))
            barrier.wait()
            ReportStore()._ensure_table(conn)
            conn.close()
        except Exception as exc:  # capture any race failure
            errors.append((name, f"{type(exc).__name__}: {exc}"))

    t1 = threading.Thread(target=worker, args=("t1",))
    t2 = threading.Thread(target=worker, args=("t2",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"Concurrent migration raised: {errors}"

    with duckdb.connect(str(db_path)) as conn:
        cols = {
            r[0]
            for r in conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'main' AND table_name = ?",
                [ReportStore.TABLE_NAME],
            ).fetchall()
        }
    assert "source_table" in cols


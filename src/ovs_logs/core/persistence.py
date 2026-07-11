"""Persistence helpers for incident reports and related artifacts."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import duckdb

from ovs_logs.core.report import IncidentReport

logger = logging.getLogger(__name__)


class ReportStore:
    """Store and retrieve ``IncidentReport`` objects in DuckDB."""

    TABLE_NAME = "_ovs_incident_reports"

    def _ensure_table(self, connection: duckdb.DuckDBPyConnection) -> None:
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE_NAME} (
                report_id VARCHAR PRIMARY KEY,
                created_at TIMESTAMP,
                report_json VARCHAR
            )
            """
        )

    def save_report(self, connection: duckdb.DuckDBPyConnection, report: IncidentReport) -> str:
        """Serialize a report and return its generated report_id."""
        self._ensure_table(connection)
        report_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).replace(tzinfo=None).isoformat()
        payload = json.dumps(report.to_dict(), ensure_ascii=False, default=str)
        connection.execute(
            f"""
            INSERT INTO {self.TABLE_NAME} (report_id, created_at, report_json)
            VALUES (?, ?, ?)
            """,
            [report_id, created_at, payload],
        )
        return report_id

    def get_report(self, connection: duckdb.DuckDBPyConnection, report_id: str) -> IncidentReport:
        """Retrieve a report by its id."""
        row = connection.execute(
            f"SELECT report_json FROM {self.TABLE_NAME} WHERE report_id = ?",
            [report_id],
        ).fetchone()
        if row is None:
            raise ValueError(f"Report not found: {report_id}")
        return IncidentReport.from_dict(json.loads(row[0]))

    def get_all_reports(self, connection: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
        """Return all stored reports ordered by created_at descending.

        Corrupted rows are skipped with a warning log so a single bad record
        does not crash the UI.
        """
        self._ensure_table(connection)
        rows = connection.execute(
            f"SELECT report_id, created_at, report_json FROM {self.TABLE_NAME} ORDER BY created_at DESC"
        ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            report_id, created_at, payload = row
            try:
                report = IncidentReport.from_dict(json.loads(payload))
            except (ValueError, TypeError, KeyError) as exc:
                logger.warning("Skipping corrupted report %s: %s", report_id, exc)
                continue
            results.append(
                {
                    "report_id": report_id,
                    "created_at": created_at,
                    "report": report,
                }
            )
        return results

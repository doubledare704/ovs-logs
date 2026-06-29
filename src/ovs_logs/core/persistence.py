"""Persistence helpers for incident reports and related artifacts."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import duckdb

from ovs_logs.core.report import IncidentReport


class ReportStore:
    """Store and retrieve ``IncidentReport`` objects in DuckDB."""

    TABLE_NAME = "incident_reports"

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

    def save_report(
        self, connection: duckdb.DuckDBPyConnection, report: IncidentReport
    ) -> str:
        """Serialize a report and return its generated report_id."""
        self._ensure_table(connection)
        report_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        payload = json.dumps(report.to_dict(), ensure_ascii=False, default=str)
        connection.execute(
            f"""
            INSERT INTO {self.TABLE_NAME} (report_id, created_at, report_json)
            VALUES (?, ?, ?)
            """,
            [report_id, created_at, payload],
        )
        return report_id

    def get_report(
        self, connection: duckdb.DuckDBPyConnection, report_id: str
    ) -> IncidentReport:
        """Retrieve a report by its id."""
        row = connection.execute(
            f"SELECT report_json FROM {self.TABLE_NAME} WHERE report_id = ?",
            [report_id],
        ).fetchone()
        if row is None:
            raise ValueError(f"Report not found: {report_id}")
        return IncidentReport.from_dict(json.loads(row[0]))

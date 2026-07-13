"""Persistence helpers for incident reports and related artifacts."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import duckdb

from ovs_logs.core.report import IncidentReport
from ovs_logs.core.sql_utils import quote_identifier

logger = logging.getLogger(__name__)

LEGACY_TABLE_NAME = "incident_reports"


class ReportStore:
    """Store and retrieve ``IncidentReport`` objects in DuckDB."""

    TABLE_NAME = "_ovs_incident_reports"

    def _migrate_legacy_table(self, connection: duckdb.DuckDBPyConnection) -> None:
        try:
            existing = {
                row[0]
                for row in connection.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
                ).fetchall()
            }
        except duckdb.Error:
            return
        if LEGACY_TABLE_NAME in existing and self.TABLE_NAME not in existing:
            connection.execute(
                f"ALTER TABLE {quote_identifier(LEGACY_TABLE_NAME)} RENAME TO {quote_identifier(self.TABLE_NAME)}"
            )

    def _ensure_table(self, connection: duckdb.DuckDBPyConnection) -> None:
        self._migrate_legacy_table(connection)
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {quote_identifier(self.TABLE_NAME)} (
                report_id VARCHAR PRIMARY KEY,
                created_at TIMESTAMP,
                report_json VARCHAR,
                source_table VARCHAR
            )
            """
        )
        self._add_source_table_column(connection)

    def _add_source_table_column(self, connection: duckdb.DuckDBPyConnection) -> None:
        """Ensure the ``source_table`` column exists on already-created tables."""
        try:
            existing = {
                row[0]
                for row in connection.execute(
                    "SELECT column_name FROM information_schema.columns WHERE table_schema = 'main' AND table_name = ?",
                    [self.TABLE_NAME],
                ).fetchall()
            }
        except duckdb.Error:
            return
        if "source_table" not in existing:
            connection.execute(f"ALTER TABLE {quote_identifier(self.TABLE_NAME)} ADD COLUMN source_table VARCHAR")

    def save_report(
        self,
        connection: duckdb.DuckDBPyConnection,
        report: IncidentReport,
        source_table: str | None = None,
    ) -> str:
        """Serialize a report and return its generated report_id."""
        self._ensure_table(connection)
        report_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).replace(tzinfo=None).isoformat()
        payload = json.dumps(report.to_dict(), ensure_ascii=False, default=str)
        connection.execute(
            f"""
            INSERT INTO {quote_identifier(self.TABLE_NAME)} (report_id, created_at, report_json, source_table)
            VALUES (?, ?, ?, ?)
            """,
            [report_id, created_at, payload, source_table],
        )
        return report_id

    def get_report(self, connection: duckdb.DuckDBPyConnection, report_id: str) -> IncidentReport:
        """Retrieve a report by its id."""
        self._ensure_table(connection)
        row = connection.execute(
            f"SELECT report_json FROM {quote_identifier(self.TABLE_NAME)} WHERE report_id = ?",
            [report_id],
        ).fetchone()
        if row is None:
            raise ValueError(f"Report not found: {report_id}")
        return IncidentReport.from_dict(json.loads(row[0]))

    def get_all_reports(
        self,
        connection: duckdb.DuckDBPyConnection,
        source_table: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return stored reports ordered by created_at descending.

        When ``source_table`` is provided, only reports scoped to that table are
        returned, plus legacy reports with no ``source_table`` so pre-migration
        records remain visible everywhere. Corrupted rows are skipped with a
        warning log so a single bad record does not crash the UI.
        """
        self._ensure_table(connection)
        if source_table is None:
            rows = connection.execute(
                f"SELECT report_id, created_at, report_json "
                f"FROM {quote_identifier(self.TABLE_NAME)} ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = connection.execute(
                f"SELECT report_id, created_at, report_json "
                f"FROM {quote_identifier(self.TABLE_NAME)} "
                f"WHERE source_table = ? OR source_table IS NULL "
                f"ORDER BY created_at DESC",
                [source_table],
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

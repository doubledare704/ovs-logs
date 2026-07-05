"""Execution engine for running anomaly detection SQL templates."""

from __future__ import annotations

from typing import Any

import duckdb

from .templates import TEMPLATES, SQLTemplate


_ALIAS_MAP: dict[str, str] = {
    "event_timestamp": "timestamp",
}


class AnalysisEngine:
    """Runs parameterized SQL templates against the unified `events` table."""

    def __init__(self, templates: dict[str, SQLTemplate] | None = None) -> None:
        self.templates = templates or TEMPLATES

    def _resolve_parameters(self, template: SQLTemplate, thresholds: dict[str, int] | None) -> list[int]:
        """Build the ordered parameter list for a template."""
        thresholds = thresholds or {}
        return [thresholds.get(param, template.default_thresholds[param]) for param in template.parameters]

    def _build_aliased_query(self, sql: str, table_name: str, connection: duckdb.DuckDBPyConnection) -> str:
        """Wrap the target table so normalized aliases resolve on raw tables.

        When querying a raw table that uses ``timestamp`` instead of
        ``event_timestamp``, this injects a lightweight ``FROM (<query>)`` wrap
        so template SQL can continue to reference ``event_timestamp`` without
        failing at bind time.
        """
        try:
            columns = [row[0] for row in connection.execute(f'DESCRIBE "{table_name}"').fetchall()]
        except Exception:
            return sql.replace("FROM events", f'FROM "{table_name}"')

        lower_columns = {c.lower() for c in columns}
        missing: list[str] = []
        expressions: list[str] = []
        for target in ("event_timestamp", "source_ip", "event_type", "status_code", "raw_message"):
            if target in lower_columns:
                expressions.append(f'"{target}"')
            elif target == "event_timestamp" and "timestamp" in lower_columns:
                expressions.append('TRY_CAST("timestamp" AS TIMESTAMP) AS "event_timestamp"')
            else:
                expressions.append(f'NULL::{_column_dtype(target, columns)} AS "{target}"')
                missing.append(target)

        if not missing:
            return sql.replace("FROM events", f'FROM (SELECT {", ".join(expressions)} FROM "{table_name}")')

        return sql.replace("FROM events", f'FROM "{table_name}"')

    def run_queries(
        self,
        connection: duckdb.DuckDBPyConnection,
        table_name: str = "events",
        thresholds: dict[str, dict[str, int]] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Execute all registered templates and return structured results.

        Args:
            connection: An active DuckDB connection.
            table_name: DuckDB table to query (defaults to ``events``).
            thresholds: Optional per-template overrides. Example:
                ``{"top_talkers": {"min_events": 5, "limit": 20}}``.

        Returns:
            A dictionary mapping template name to a list of result rows, where
            each row is a dictionary of column-name -> value.
        """
        thresholds = thresholds or {}
        results: dict[str, list[dict[str, Any]]] = {}

        for name, template in self.templates.items():
            if table_name == "events":
                sql = template.sql
            else:
                sql = self._build_aliased_query(template.sql, table_name, connection)
            params = self._resolve_parameters(template, thresholds.get(name))
            cursor = connection.execute(sql, params)
            columns = [desc[0] for desc in cursor.description]
            results[name] = [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]

        return results


def _column_dtype(target: str, columns: list[str]) -> str:
    if target == "event_timestamp":
        return "TIMESTAMP"
    if target == "status_code":
        return "BIGINT"
    return "VARCHAR"

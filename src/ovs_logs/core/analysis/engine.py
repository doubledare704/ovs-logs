"""Execution engine for running anomaly detection SQL templates."""

from __future__ import annotations

import logging
from typing import Any

import duckdb

from ..ingestion.adapters import _timestamp_cast_expression
from ..sql_utils import quote_identifier as _quote_identifier
from .templates import TEMPLATES, SQLTemplate

_ALIAS_MAP: dict[str, str] = {
    "event_timestamp": "timestamp",
}

logger = logging.getLogger(__name__)


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
            columns = connection.execute(f"DESCRIBE {_quote_identifier(table_name)}").fetchall()
        except duckdb.Error:
            logger.warning("DESCRIBE failed for table %s; using raw table reference", table_name)
            return sql.replace("FROM events", f"FROM {_quote_identifier(table_name)}")

        column_types = {row[0].lower(): str(row[1]) for row in columns}
        lower_columns = set(column_types)
        expressions: list[str] = []
        for target in ("event_timestamp", "source_ip", "event_type", "status_code", "raw_message"):
            if target in lower_columns:
                if target == "status_code" and _is_string_type(column_types[target]):
                    expressions.append(f'CAST(NULLIF("{target}", \'\') AS BIGINT) AS "{target}"')
                else:
                    expressions.append(f'"{target}"')
            elif target == "event_timestamp" and "timestamp" in lower_columns:
                expressions.append(f'{_timestamp_cast_expression("timestamp")} AS "event_timestamp"')
            elif target == "event_type" and "event" in lower_columns:
                expressions.append('"event"::VARCHAR AS "event_type"')
            elif target == "raw_message" and "message" in lower_columns:
                expressions.append('"message"::VARCHAR AS "raw_message"')
            else:
                expressions.append(f'NULL::{_column_dtype(target)} AS "{target}"')

        return sql.replace(
            "FROM events",
            f"FROM (SELECT {', '.join(expressions)} FROM {_quote_identifier(table_name)})",
        )

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


def _is_string_type(dtype: str) -> bool:
    """Return True if a DuckDB column type is a textual type needing casting."""
    return "VARCHAR" in dtype or "CHAR" in dtype or "STRING" in dtype or "TEXT" in dtype


def _column_dtype(target: str) -> str:
    if target == "event_timestamp":
        return "TIMESTAMP"
    if target == "status_code":
        return "BIGINT"
    return "VARCHAR"

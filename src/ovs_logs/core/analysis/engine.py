"""Execution engine for running anomaly detection SQL templates."""

from __future__ import annotations

from typing import Any

import duckdb

from .templates import SQLTemplate, TEMPLATES


class AnalysisEngine:
    """Runs parameterized SQL templates against the unified `events` table."""

    def __init__(self, templates: dict[str, SQLTemplate] | None = None) -> None:
        self.templates = templates or TEMPLATES

    def _resolve_parameters(
        self, template: SQLTemplate, thresholds: dict[str, int] | None
    ) -> list[int]:
        """Build the ordered parameter list for a template."""
        thresholds = thresholds or {}
        return [
            thresholds.get(param, template.default_thresholds[param])
            for param in template.parameters
        ]

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
            sql = template.sql.replace("FROM events", f'FROM "{table_name}"')
            params = self._resolve_parameters(template, thresholds.get(name))
            cursor = connection.execute(sql, params)
            columns = [desc[0] for desc in cursor.description]
            results[name] = [dict(zip(columns, row)) for row in cursor.fetchall()]

        return results

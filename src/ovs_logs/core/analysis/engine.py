"""Execution engine for running anomaly detection SQL templates."""

from __future__ import annotations

import logging
from typing import Any

import duckdb

from ..constants import NORMALIZED_COLUMNS
from ..normalization import FIELD_ALIASES
from ..sql_utils import quote_identifier as _quote_identifier, timestamp_cast_expression
from .templates import TEMPLATES, SQLTemplate

logger = logging.getLogger(__name__)


def _find_matched_alias(target: str, lower_columns: set[str]) -> str | None:
    """Find the first alias for the target field that exists in lower_columns."""
    for alias in FIELD_ALIASES.get(target, []):
        if alias in lower_columns:
            return alias
    return None


def _status_code_expression(column: str, column_types: dict[str, str]) -> str:
    """Build the ``status_code`` cast expression for ``column``.

    Uses ``TRY_CAST(NULLIF(TRIM(...)))`` for textual columns and a direct
    ``BIGINT`` cast otherwise. ``column`` must already be an original-case
    column name; it is quoted safely here.
    """
    quoted = _quote_identifier(column)
    if _is_string_type(column_types[column.lower()]):
        return f"TRY_CAST(NULLIF(TRIM({quoted}), '') AS BIGINT)"
    return f"{quoted}::BIGINT"


def _build_expression_for_matched_alias(
    target: str,
    matched_alias: str,
    column_types: dict[str, str],
    orig_columns: dict[str, str],
) -> str:
    """Build select expression when an alias is matched.

    ``orig_columns`` maps lowercased column names back to their original,
    case-preserved names so quoted identifiers match DuckDB's case-sensitive
    quoted-identifier semantics.
    """
    orig_name = orig_columns[matched_alias]
    if target == "event_timestamp":
        return f'{timestamp_cast_expression(orig_name)} AS "event_timestamp"'
    if target == "status_code":
        return f'{_status_code_expression(orig_name, column_types)} AS "status_code"'
    return f'{_quote_identifier(orig_name)}::{_column_dtype(target)} AS "{target}"'


def _build_expression_for_target(
    target: str,
    lower_columns: set[str],
    column_types: dict[str, str],
    orig_columns: dict[str, str],
) -> str:
    """Build the SQL select expression for a single target column.

    ``orig_columns`` maps lowercased column names to their original case so the
    generated SQL quotes identifiers with their real casing.
    """
    if target in lower_columns:
        orig_name = orig_columns[target]
        if target == "status_code" and _is_string_type(column_types[target]):
            return f'{_status_code_expression(orig_name, column_types)} AS "{target}"'
        return f'{_quote_identifier(orig_name)} AS "{target}"'

    matched_alias = _find_matched_alias(target, lower_columns)
    if matched_alias is not None:
        return _build_expression_for_matched_alias(target, matched_alias, column_types, orig_columns)

    return f'NULL::{_column_dtype(target)} AS "{target}"'


def build_aliased_query(sql: str, table_name: str, connection: duckdb.DuckDBPyConnection) -> str:
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
    orig_columns = {row[0].lower(): row[0] for row in columns}
    lower_columns = set(column_types)
    expressions = [
        _build_expression_for_target(target, lower_columns, column_types, orig_columns) for target in NORMALIZED_COLUMNS
    ]

    aliased_from = f"FROM (SELECT {', '.join(expressions)} FROM {_quote_identifier(table_name)})"
    return sql.replace("FROM events", aliased_from).replace("FROM __EVENTS_TABLE__", aliased_from)


class AnalysisEngine:
    """Runs parameterized SQL templates against the unified `events` table."""

    def __init__(self, templates: dict[str, SQLTemplate] | None = None) -> None:
        self.templates = templates or TEMPLATES

    def _resolve_parameters(self, template: SQLTemplate, thresholds: dict[str, int] | None) -> list[int]:
        """Build the ordered parameter list for a template."""
        thresholds = thresholds or {}
        return [thresholds.get(param, template.default_thresholds[param]) for param in template.parameters]

    def run_queries(
        self,
        connection: duckdb.DuckDBPyConnection,
        table_name: str = "events",
        thresholds: dict[str, dict[str, int]] | None = None,
        template_names: list[str] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Execute templates and return structured results.

        Args:
            connection: An active DuckDB connection.
            table_name: DuckDB table to query (defaults to ``events``).
            thresholds: Optional per-template overrides. Example:
                ``{"top_talkers": {"min_events": 5, "limit": 20}}``.
            template_names: Subset of template names to run. When
                ``None`` (default), all registered templates are executed.

        Returns:
            A dictionary mapping template name to a list of result rows, where
            each row is a dictionary of column-name -> value.
        """
        thresholds = thresholds or {}
        results: dict[str, list[dict[str, Any]]] = {}

        templates_to_run = {
            name: tmpl for name, tmpl in self.templates.items() if template_names is None or name in template_names
        }

        for name, template in templates_to_run.items():
            sql = template.sql if table_name == "events" else build_aliased_query(template.sql, table_name, connection)
            sql = sql.replace("__EVENTS_TABLE__", "events" if table_name == "events" else _quote_identifier(table_name))
            params = self._resolve_parameters(template, thresholds.get(name))
            try:
                cursor = connection.execute(sql, params)
            except duckdb.BinderException:
                logger.warning(
                    "Skipping template '%s' — required columns not found in table '%s'",
                    name,
                    table_name,
                )
                continue
            columns = [desc[0] for desc in cursor.description]
            results[name] = [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]

        return results


def _is_string_type(dtype: str) -> bool:
    """Return True if a DuckDB column type is a textual type needing casting."""
    return "VARCHAR" in dtype or "CHAR" in dtype or "STRING" in dtype or "TEXT" in dtype


def _column_dtype(target: str) -> str:
    """Return the DuckDB SQL type for a normalized column name."""
    if target == "event_timestamp":
        return "TIMESTAMP"
    if target == "status_code":
        return "BIGINT"
    return "VARCHAR"

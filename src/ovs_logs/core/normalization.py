"""Normalize raw DuckDB tables into a unified `events` schema."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import duckdb

from ovs_logs.core.ingestion.adapters import LoadResult

FIELD_ALIASES: dict[str, list[str]] = {
    "event_timestamp": [
        "timestamp",
        "event_timestamp",
        "time",
        "date",
        "ts",
        "datetime",
        "event_time",
        "created_at",
    ],
    "source_ip": [
        "client_ip",
        "remote_addr",
        "src_ip",
        "source_ip",
        "ip",
        "remote_ip",
        "client",
    ],
    "event_type": [
        "event",
        "event_type",
        "action",
        "method",
        "request_method",
        "type",
    ],
    "status_code": [
        "status",
        "status_code",
        "http_status",
        "response_code",
        "code",
    ],
    "raw_message": [
        "message",
        "raw_message",
        "line",
        "log",
        "raw",
    ],
}

TARGET_TYPES: dict[str, str] = {
    "event_timestamp": "TIMESTAMP",
    "source_ip": "VARCHAR",
    "event_type": "VARCHAR",
    "status_code": "INTEGER",
    "raw_message": "VARCHAR",
}


@dataclass(frozen=True)
class NormalizeResult:
    """Result of transforming a raw table into the unified `events` schema."""

    table_name: str
    row_count: int
    mapping: dict[str, str | None]
    schema: Sequence[tuple[str, str]]


class NormalizationEngine:
    """Maps raw DuckDB tables into the standard OVS-Log `events` schema."""

    def __init__(self, aliases: dict[str, list[str]] | None = None) -> None:
        self.aliases = aliases or FIELD_ALIASES

    def _find_matches(self, columns: Sequence[str], target: str) -> list[str]:
        """Return raw column names that match any alias for the target field."""
        lower_map = {c.lower(): c for c in columns}
        candidates = self.aliases.get(target, [])
        return [lower_map[alias] for alias in candidates if alias in lower_map]

    def _build_expression(self, target: str, dtype: str, matches: list[str]) -> tuple[str, str | None]:
        """Return a SQL select expression and the source column used (if any)."""
        if not matches:
            return f'NULL::{dtype} AS "{target}"', None

        source_column = matches[0]
        if target in {"event_timestamp", "status_code"}:
            casts = ", ".join(f'try_cast("{col}" AS {dtype})' for col in matches)
        else:
            casts = ", ".join(f'"{col}"::{dtype}' for col in matches)

        return f'COALESCE({casts}) AS "{target}"', source_column

    def build_select_query(self, raw_table: str, columns: Sequence[str]) -> tuple[str, dict[str, str | None]]:
        """Build the `SELECT ... FROM "raw_table"` SQL statement."""
        expressions: list[str] = []
        mapping: dict[str, str | None] = {}

        for target, dtype in TARGET_TYPES.items():
            matches = self._find_matches(columns, target)
            expr, source = self._build_expression(target, dtype, matches)
            expressions.append(expr)
            mapping[target] = source

        select_sql = ",\n    ".join(expressions)
        query = f'SELECT\n    {select_sql}\nFROM "{raw_table}"'
        return query, mapping

    def build_sql(self, raw_table: str, columns: Sequence[str]) -> tuple[str, dict[str, str | None]]:
        """Build the `CREATE OR REPLACE TABLE events AS ...` SQL statement."""
        select_query, mapping = self.build_select_query(raw_table, columns)
        return (
            f"CREATE OR REPLACE TABLE events AS {select_query}",
            mapping,
        )

    def normalize_table(self, connection: duckdb.DuckDBPyConnection, load_result: LoadResult) -> NormalizeResult:
        """Create or replace the unified `events` table from a raw load result."""
        raw_columns = [name for name, _ in load_result.schema]
        sql, mapping = self.build_sql(load_result.table_name, raw_columns)

        connection.execute(sql)

        row_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        schema_rows = connection.execute("DESCRIBE events").fetchall()
        schema = [(row[0], row[1]) for row in schema_rows]

        return NormalizeResult(
            table_name="events",
            row_count=row_count,
            mapping=mapping,
            schema=schema,
        )

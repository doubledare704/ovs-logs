"""Normalize raw DuckDB tables into a unified `events` schema."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass

import duckdb

from ovs_logs.core.ingestion.adapters import LoadResult, _timestamp_cast_expression
from ovs_logs.core.sql_utils import quote_identifier

logger = logging.getLogger(__name__)

# Internal bookkeeping table recording which raw tables have already been merged
# into ``events``, so ``normalize_batch`` stays idempotent across re-runs. The
# ``_ovs_`` prefix keeps it out of the UI "Recent Tables" navigator.
_SOURCE_TRACKING_TABLE = "_ovs_normalized_sources"
_TRACKING_TABLE_QUOTED = quote_identifier(_SOURCE_TRACKING_TABLE)

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
        if target == "event_timestamp":
            return f'{_timestamp_cast_expression(source_column)} AS "{target}"', source_column
        if target == "status_code":
            casts = ", ".join(f"try_cast({quote_identifier(col)} AS {dtype})" for col in matches)
        else:
            casts = ", ".join(f"{quote_identifier(col)}::{dtype}" for col in matches)

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
        query = f"SELECT\n    {select_sql}\nFROM {quote_identifier(raw_table)}"
        return query, mapping

    def build_sql(self, raw_table: str, columns: Sequence[str]) -> tuple[str, dict[str, str | None]]:
        """Build the `CREATE OR REPLACE TABLE events AS ...` SQL statement."""
        select_query, mapping = self.build_select_query(raw_table, columns)
        return (
            f"CREATE OR REPLACE TABLE events AS {select_query}",
            mapping,
        )

    def normalize_batch(
        self,
        connection: duckdb.DuckDBPyConnection,
        tables: Sequence[tuple[str, Sequence[str]]],
    ) -> int:
        """Normalize multiple raw tables into the unified ``events`` table.

        Builds a ``UNION ALL`` of the per-table normalized ``SELECT`` queries and
        writes them into ``events``. When ``events`` already exists the rows are
        appended (``INSERT INTO``); otherwise the table is created. This avoids the
        silent data loss that ``CREATE OR REPLACE`` would cause on repeated batches.

        The call is idempotent per source table: raw tables that have already been
        merged into ``events`` (tracked in ``_ovs_normalized_sources``) are skipped
        so re-running ingestion over the same sources does not accumulate duplicate
        rows. Deduplication is intentionally by source table, not by row content, so
        legitimately repeated log lines are preserved.

        Args:
            connection: An active DuckDB connection.
            tables: Sequence of ``(raw_table_name, columns)`` pairs to normalize.

        Returns:
            The total row count of the ``events`` table after the batch, or ``0``
            when there is nothing to normalize and ``events`` does not yet exist.
        """
        candidates = [(raw_table, list(columns)) for raw_table, columns in tables if raw_table and columns]

        existing = {row[0] for row in connection.execute("SHOW TABLES").fetchall()}
        events_exists = "events" in existing

        connection.execute(f"CREATE TABLE IF NOT EXISTS {_TRACKING_TABLE_QUOTED} (raw_table VARCHAR PRIMARY KEY)")
        already_merged = {
            row[0] for row in connection.execute(f"SELECT raw_table FROM {_TRACKING_TABLE_QUOTED}").fetchall()
        }

        new_tables = [(raw_table, columns) for raw_table, columns in candidates if raw_table not in already_merged]
        if not new_tables:
            return self._events_row_count(connection) if events_exists else 0

        union_query = " UNION ALL ".join(
            self.build_select_query(raw_table, columns)[0] for raw_table, columns in new_tables
        )
        if events_exists:
            connection.execute(f"INSERT INTO events {union_query}")
        else:
            connection.execute(f"CREATE TABLE events AS {union_query}")

        connection.executemany(
            f"INSERT INTO {_TRACKING_TABLE_QUOTED} VALUES (?)",
            [(raw_table,) for raw_table, _ in new_tables],
        )

        return self._events_row_count(connection)

    @staticmethod
    def _events_row_count(connection: duckdb.DuckDBPyConnection) -> int:
        """Return the current row count of the ``events`` table (0 if absent)."""
        row = connection.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0] if row is not None else 0

    def normalize_table(self, connection: duckdb.DuckDBPyConnection, load_result: LoadResult) -> NormalizeResult:
        """Create or replace the unified `events` table from a raw load result."""
        raw_columns = [name for name, _ in load_result.schema]
        sql, mapping = self.build_sql(load_result.table_name, raw_columns)

        connection.execute(sql)

        row = connection.execute("SELECT COUNT(*) FROM events").fetchone()
        row_count = row[0] if row is not None else 0
        schema_rows = connection.execute("DESCRIBE events").fetchall()
        schema = [(row[0], row[1]) for row in schema_rows]

        return NormalizeResult(
            table_name="events",
            row_count=row_count,
            mapping=mapping,
            schema=schema,
        )

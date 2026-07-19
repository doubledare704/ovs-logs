"""Attack-timeline aggregation over a DuckDB log table.

Provides pure (Streamlit-free) logic that computes headline timeline metrics and
a chronological list of events for the OVD-53 timeline tab. It reuses the same
alias-wrapping the ``AnalysisEngine`` uses so it works on both the normalized
``events`` table and raw sidebar tables.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

import duckdb

from ovs_logs.core.analysis.engine import build_aliased_query

logger = logging.getLogger(__name__)

DEFAULT_TIMELINE_LIMIT = 500


@dataclass(frozen=True)
class TimelineMetrics:
    """Headline statistics for the incident chronology."""

    total_events: int
    first_event: datetime | None
    last_event: datetime | None
    duration: str | None
    unique_source_ips: int
    error_count: int
    error_rate_pct: float


@dataclass(frozen=True)
class TimelineRow:
    """A single chronologically ordered event row."""

    timestamp: datetime | None
    source_ip: str | None
    event_type: str | None
    status_code: int | None
    raw_message: str | None


def _format_duration(span: timedelta) -> str:
    """Render a ``timedelta`` as a compact string, dropping zero components."""
    total_seconds = int(span.total_seconds())
    if total_seconds <= 0:
        return "0s"

    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def _build_where_clauses(
    *,
    source_ip: str | list[str] | None = None,
    min_status: int | None = None,
    event_type: str | list[str] | None = None,
) -> tuple[list[str], list[object]]:
    """Build SQL WHERE fragment and parameter list from optional filters.

    Single values produce ``= ?`` clauses; lists (non-empty) produce
    ``IN (?, ?, ...)`` clauses. Returns ``([], [])`` when no filters are set.
    """
    clauses: list[str] = []
    params: list[object] = []

    if source_ip is not None:
        if isinstance(source_ip, list):
            if source_ip:
                placeholders = ", ".join("?" for _ in source_ip)
                clauses.append(f'"source_ip" IN ({placeholders})')
                params.extend(source_ip)
        else:
            clauses.append('"source_ip" = ?')
            params.append(source_ip)

    if min_status is not None:
        clauses.append('"status_code" >= ?')
        params.append(min_status)

    if event_type is not None:
        if isinstance(event_type, list):
            if event_type:
                placeholders = ", ".join("?" for _ in event_type)
                clauses.append(f'"event_type" IN ({placeholders})')
                params.extend(event_type)
        else:
            clauses.append('"event_type" = ?')
            params.append(event_type)

    return clauses, params


def _wrap_with_filters(
    base_sql: str,
    *,
    source_ip: str | list[str] | None = None,
    min_status: int | None = None,
    event_type: str | list[str] | None = None,
) -> tuple[str, list[object]]:
    """Wrap ``base_sql`` with optional WHERE filters using parameterized queries.

    Returns ``(wrapped_sql, params)``.
    """
    clauses, params = _build_where_clauses(
        source_ip=source_ip,
        min_status=min_status,
        event_type=event_type,
    )
    if not clauses:
        return base_sql, params
    where = " AND ".join(clauses)
    return f"SELECT * FROM ({base_sql}) AS _filtered WHERE {where}", params


def _build_metrics_query(sql: str) -> str:
    return (
        "SELECT COUNT(*) AS total_events, "
        'MIN("event_timestamp") AS first_event, '
        'MAX("event_timestamp") AS last_event, '
        'COUNT(DISTINCT "source_ip") AS unique_source_ips, '
        'COALESCE(SUM(CASE WHEN "status_code" >= 400 THEN 1 ELSE 0 END), 0)::BIGINT AS error_count '
        f"FROM ({sql}) AS _metrics"
    )


def _build_rows_query(sql: str, limit: int) -> str:
    return (
        'SELECT "event_timestamp", "source_ip", "event_type", "status_code", "raw_message" '
        f"FROM ({sql}) AS _rows "
        'ORDER BY "event_timestamp" ASC NULLS LAST '
        f"LIMIT {int(limit)}"
    )


def build_timeline(  # noqa: PLR0913
    connection: duckdb.DuckDBPyConnection,
    table_name: str = "events",
    *,
    limit: int = DEFAULT_TIMELINE_LIMIT,
    source_ip: str | list[str] | None = None,
    min_status: int | None = None,
    event_type: str | list[str] | None = None,
) -> tuple[TimelineMetrics, list[TimelineRow]]:
    """Compute timeline metrics and event rows for ``table_name``.

    Both queries are written against the normalized ``events`` schema and then
    alias-wrapped via :func:`build_aliased_query` when ``table_name`` is not the
    normalized ``events`` table, so raw sidebar tables resolve correctly.

    Args:
        connection: An active DuckDB connection.
        table_name: DuckDB table to query (defaults to ``events``).
        limit: Maximum number of event rows returned. Metrics are always computed
            over the full table.
        source_ip: If set, only include events from this IP. Accepts a single
            string or a list of strings for multi-select.
        min_status: If set, only include events with ``status_code >= min_status``.
        event_type: If set, only include events with this ``event_type``. Accepts
            a single string or a list of strings for multi-select.

    Returns:
        A ``(TimelineMetrics, list[TimelineRow])`` tuple. ``duckdb.Error`` is
        allowed to propagate so the caller can degrade gracefully.
    """
    if table_name == "events":
        wrapped = "SELECT * FROM events"
    else:
        wrapped = build_aliased_query("SELECT * FROM events", table_name, connection)

    wrapped, params = _wrap_with_filters(
        wrapped,
        source_ip=source_ip,
        min_status=min_status,
        event_type=event_type,
    )

    metrics_row = connection.execute(_build_metrics_query(wrapped), params).fetchone()
    if metrics_row is None:
        raise RuntimeError("timeline metrics query returned no row")
    total_events, first_event, last_event, unique_source_ips, error_count = metrics_row

    error_rate_pct = round(error_count / total_events * 100, 1) if total_events else 0.0

    if first_event is None or last_event is None:
        duration: str | None = None
    else:
        duration = _format_duration(last_event - first_event)

    metrics = TimelineMetrics(
        total_events=int(total_events),
        first_event=first_event,
        last_event=last_event,
        duration=duration,
        unique_source_ips=int(unique_source_ips),
        error_count=int(error_count),
        error_rate_pct=error_rate_pct,
    )

    cursor = connection.execute(_build_rows_query(wrapped, limit), params)
    rows = [
        TimelineRow(
            timestamp=timestamp,
            source_ip=source_ip_val,
            event_type=event_type_val,
            status_code=status_code,
            raw_message=raw_message,
        )
        for timestamp, source_ip_val, event_type_val, status_code, raw_message in cursor.fetchall()
    ]

    return metrics, rows


def list_timeline_filter_options(
    connection: duckdb.DuckDBPyConnection,
    table_name: str = "events",
) -> tuple[list[tuple[str, int]], list[str]]:
    """Return IP-frequency pairs and distinct event types for filter widgets.

    Both queries use the same alias-wrapping strategy as :func:`build_timeline`
    so raw sidebar tables resolve correctly.

    Returns:
        A ``(ip_counts, event_types)`` tuple where ``ip_counts`` is
        ``[(ip, count), ...]`` ordered by count descending and ``event_types``
        is a sorted list of distinct event types.
    """
    if table_name == "events":
        base = "SELECT * FROM events"
    else:
        base = build_aliased_query("SELECT * FROM events", table_name, connection)

    ip_rows = connection.execute(
        f'SELECT "source_ip", COUNT(*) AS cnt FROM ({base}) AS _opts '
        'WHERE "source_ip" IS NOT NULL '
        'GROUP BY "source_ip" '
        "ORDER BY cnt DESC",
    ).fetchall()
    ip_counts = [(str(row[0]), int(row[1])) for row in ip_rows]

    event_rows = connection.execute(
        f'SELECT DISTINCT "event_type" FROM ({base}) AS _opts WHERE "event_type" IS NOT NULL ORDER BY "event_type" ASC',
    ).fetchall()
    event_types = [str(row[0]) for row in event_rows]

    return ip_counts, event_types

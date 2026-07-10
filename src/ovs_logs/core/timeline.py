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


def _build_metrics_query(sql: str) -> str:
    return (
        "SELECT COUNT(*) AS total_events, "
        "MIN(event_timestamp) AS first_event, "
        "MAX(event_timestamp) AS last_event, "
        "COUNT(DISTINCT source_ip) AS unique_source_ips, "
        "COALESCE(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0)::BIGINT AS error_count "
        f"FROM ({sql}) AS _metrics"
    )


def _build_rows_query(sql: str, limit: int) -> str:
    return (
        "SELECT event_timestamp, source_ip, event_type, status_code, raw_message "
        f"FROM ({sql}) AS _rows "
        "ORDER BY event_timestamp ASC NULLS LAST "
        f"LIMIT {int(limit)}"
    )


def build_timeline(
    connection: duckdb.DuckDBPyConnection,
    table_name: str = "events",
    *,
    limit: int = DEFAULT_TIMELINE_LIMIT,
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

    Returns:
        A ``(TimelineMetrics, list[TimelineRow])`` tuple. ``duckdb.Error`` is
        allowed to propagate so the caller can degrade gracefully.
    """
    if table_name == "events":
        wrapped = "SELECT * FROM events"
    else:
        wrapped = build_aliased_query("SELECT * FROM events", table_name, connection)

    metrics_row = connection.execute(_build_metrics_query(wrapped)).fetchone()
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

    cursor = connection.execute(_build_rows_query(wrapped, limit))
    columns = [desc[0] for desc in cursor.description]
    rows = [
        TimelineRow(
            timestamp=row[columns.index("event_timestamp")],
            source_ip=row[columns.index("source_ip")],
            event_type=row[columns.index("event_type")],
            status_code=row[columns.index("status_code")],
            raw_message=row[columns.index("raw_message")],
        )
        for row in cursor.fetchall()
    ]

    return metrics, rows

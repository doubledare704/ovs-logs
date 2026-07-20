"""Parameterized SQL templates for anomaly detection over the `events` table."""

from __future__ import annotations

from dataclasses import dataclass

from ovs_logs.core.constants import TEMPORAL_BUCKET_INTERVAL


@dataclass(frozen=True)
class SQLTemplate:
    """A named SQL template with expected parameters and default thresholds."""

    name: str
    sql: str
    parameters: list[str]
    default_thresholds: dict[str, int]


TEMPLATES: dict[str, SQLTemplate] = {
    "top_talkers": SQLTemplate(
        name="top_talkers",
        sql=(
            "SELECT source_ip, COUNT(*) as event_count "
            "FROM events "
            "WHERE source_ip IS NOT NULL "
            "GROUP BY source_ip "
            "HAVING COUNT(*) >= ? "
            "ORDER BY event_count DESC "
            "LIMIT ?"
        ),
        parameters=["min_events", "limit"],
        default_thresholds={"min_events": 0, "limit": 10},
    ),
    "error_spikes": SQLTemplate(
        name="error_spikes",
        sql=(
            "SELECT source_ip, status_code, COUNT(*) as error_count "
            "FROM events "
            "WHERE status_code >= 400 "
            "GROUP BY source_ip, status_code "
            "HAVING COUNT(*) >= ? "
            "ORDER BY error_count DESC "
            "LIMIT ?"
        ),
        parameters=["min_errors", "limit"],
        default_thresholds={"min_errors": 0, "limit": 10},
    ),
    "event_distribution": SQLTemplate(
        name="event_distribution",
        sql=(
            "SELECT event_type, COUNT(*) as event_count "
            "FROM events "
            "WHERE event_type IS NOT NULL "
            "GROUP BY event_type "
            "ORDER BY event_count DESC "
            "LIMIT ?"
        ),
        parameters=["limit"],
        default_thresholds={"limit": 10},
    ),
    "temporal_anomaly": SQLTemplate(
        name="temporal_anomaly",
        sql=(
            f"SELECT time_bucket(INTERVAL '{TEMPORAL_BUCKET_INTERVAL}', event_timestamp) as time_bucket, "
            "COUNT(*) as event_count "
            "FROM events "
            "WHERE event_timestamp IS NOT NULL "
            "GROUP BY time_bucket "
            "HAVING COUNT(*) >= ? "
            "ORDER BY event_count DESC "
            "LIMIT ?"
        ),
        parameters=["min_events", "limit"],
        default_thresholds={"min_events": 0, "limit": 10},
    ),
}

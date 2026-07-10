"""Attack-timeline rendering for the OVS-Log Streamlit dashboard.

Thin wrapper around the core ``build_timeline`` aggregation. UI degrades to an
informational message for tables without analyzable fields, empty tables, or
query errors instead of failing.
"""

from __future__ import annotations

import logging

import duckdb
import streamlit as st

from ovs_logs.core.timeline import build_timeline
from ovs_logs.ui.analysis_view import has_analyzable_columns

logger = logging.getLogger(__name__)


def render_timeline_card(connection: duckdb.DuckDBPyConnection, table_name: str) -> None:
    """Render the Attack Timeline card: 4 metric tiles + a sortable event table.

    Degrades gracefully for non-analyzable / empty tables and query errors.
    """
    if not has_analyzable_columns(connection, table_name):
        st.info("No analyzable fields in this table")
        return

    try:
        metrics, rows = build_timeline(connection, table_name)
    except duckdb.Error:
        logger.exception("Failed to build timeline for table %s", table_name)
        st.error("Timeline failed while querying this table.")
        return

    if metrics.total_events == 0:
        st.info("No events found in this table.")
        return

    cols = st.columns(4)
    cols[0].metric("Total events", metrics.total_events)
    cols[1].metric("Time span", metrics.duration or "n/a")
    cols[2].metric("Unique source IPs", metrics.unique_source_ips)
    cols[3].metric("Error rate", f"{metrics.error_rate_pct}%")

    st.dataframe(
        rows,
        hide_index=True,
        width="stretch",
        column_config={
            "timestamp": "Timestamp",
            "source_ip": "Source IP",
            "event_type": "Event Type",
            "status_code": "Status",
            "raw_message": "Message",
        },
    )

    if metrics.total_events > len(rows):
        st.caption(f"Showing first {len(rows)} of {metrics.total_events} events; the table is sortable and filterable.")

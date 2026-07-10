"""Live analysis rendering for the OVS-Log Streamlit dashboard.

Reuses the core ``AnalysisEngine`` and ``IndicatorProcessor`` so the UI shows
the same suspicious indicators the CLI produces, without duplicating analysis
logic. Analysis is best-effort: tables without analyzable fields or that raise
a query error degrade to an informational message instead of failing.
"""

from __future__ import annotations

import logging

import duckdb
import streamlit as st

from ovs_logs.core.analysis import AnalysisEngine, IndicatorProcessor
from ovs_logs.core.sql_utils import quote_identifier

logger = logging.getLogger(__name__)

_ANALYZABLE_COLUMNS = {
    "event_timestamp",
    "timestamp",
    "source_ip",
    "event_type",
    "status_code",
    "event",
    "raw_message",
    "message",
    "line",
}


def has_analyzable_columns(connection: duckdb.DuckDBPyConnection, table_name: str) -> bool:
    """Return True when the table exposes at least one normalized column."""
    try:
        columns = [row[0] for row in connection.execute(f"DESCRIBE {quote_identifier(table_name)}").fetchall()]
    except duckdb.Error:
        return False
    return any(col.lower() in _ANALYZABLE_COLUMNS for col in columns)


def render_analysis_results(connection: duckdb.DuckDBPyConnection, table_name: str) -> None:
    """Render suspicious indicators for ``table_name`` as a Streamlit table.

    Catches query errors and tables without analyzable fields, showing an
    informational fallback instead. No LLM or AbuseIPDB calls are made.
    """
    if not has_analyzable_columns(connection, table_name):
        st.info("No analyzable fields in this table")
        return

    try:
        raw_results = AnalysisEngine().run_queries(connection, table_name=table_name)
        indicators = IndicatorProcessor().process(raw_results)
    except duckdb.Error:
        logger.exception("Failed to analyze table %s", table_name)
        st.error("Analysis failed while querying or processing this table.")
        return

    if not indicators:
        st.info("No suspicious indicators found in this table.")
        return

    rows = [
        {
            "Type": indicator.type,
            "Severity": indicator.severity,
            "Description": indicator.description,
            "Evidence": str(indicator.evidence),
        }
        for indicator in indicators
    ]
    st.dataframe(rows, width="stretch", hide_index=True)

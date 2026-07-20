"""Live analysis rendering for the OVS-Log Streamlit dashboard.

Reuses the core ``AnalysisEngine`` and ``IndicatorProcessor`` so the UI shows
the same suspicious indicators the CLI produces, without duplicating analysis
logic. Analysis is best-effort: tables without analyzable fields or that raise
a query error degrade to an informational message instead of failing.
"""

from __future__ import annotations

import dataclasses
import logging

import duckdb
import streamlit as st

from ovs_logs.config.settings import settings
from ovs_logs.core.analysis import AnalysisEngine, IndicatorProcessor
from ovs_logs.core.analysis.indicators import SuspiciousIndicator, extract_unique_ips
from ovs_logs.core.normalization import get_all_aliases
from ovs_logs.core.sql_utils import quote_identifier
from ovs_logs.core.threat_lists import is_loaded as tl_is_loaded, match_ips as tl_match_ips

logger = logging.getLogger(__name__)


def has_analyzable_columns(connection: duckdb.DuckDBPyConnection, table_name: str) -> bool:
    """Return True when the table exposes at least one normalized column."""
    try:
        columns = [row[0].lower() for row in connection.execute(f"DESCRIBE {quote_identifier(table_name)}").fetchall()]
    except duckdb.Error:
        return False

    all_analyzable = get_all_aliases()
    return any(col in all_analyzable for col in columns)


def compute_indicators(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
) -> list[SuspiciousIndicator] | None:
    """Run analysis and return enriched indicators with threat-list matches.

    Returns ``None`` when the table has no analyzable columns (``None`` means
    *only* non-analyzable). Query failures propagate as ``duckdb.Error``.
    Otherwise returns a list of enriched ``SuspiciousIndicator``
    objects with potential threat-list matches attached.
    """
    if not has_analyzable_columns(connection, table_name):
        return None

    raw_results = AnalysisEngine().run_queries(connection, table_name=table_name)
    indicators = IndicatorProcessor().process(raw_results)

    if not indicators:
        return []

    # Enrich with threat-list matches (best-effort, never breaks analysis)
    try:
        enabled = st.session_state.get(
            "threat_lists_enabled",
            list(settings.threat_lists.default_lists),
        )
        cache_dir = settings.threat_lists.cache_dir
        if enabled and tl_is_loaded(enabled, cache_dir):
            ips = extract_unique_ips(indicators)
            hits = tl_match_ips(ips, enabled, cache_dir)
            if hits:
                enriched: list[SuspiciousIndicator] = []
                for ind in indicators:
                    ip = ind.evidence.get("source_ip", "")
                    if isinstance(ip, str) and ip in hits:
                        enriched.append(dataclasses.replace(ind, threat_lists=hits[ip]))
                    else:
                        enriched.append(ind)
                indicators = enriched
    except (OSError, ValueError):
        logger.exception("Threat-list enrichment failed, continuing without")

    return indicators


def render_analysis_results(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    indicators: list[SuspiciousIndicator] | None = None,
) -> None:
    """Render suspicious indicators for ``table_name`` as a Streamlit table.

    When *indicators* is ``None`` (the default), the indicators are computed
    from *connection* and *table_name* on the fly.  Pre-computed results may
    be passed in to avoid duplicate computation when the caller already has
    them.
    """
    if indicators is None:
        try:
            indicators = compute_indicators(connection, table_name)
        except duckdb.Error as exc:
            st.error(f"Unable to analyze this table: {exc}")
            return

    if indicators is None:
        st.info("No analyzable fields in this table")
        return

    if not indicators:
        st.info("No suspicious indicators found in this table.")
        return

    any_threat = any(bool(ind.threat_lists) for ind in indicators)
    rows = [
        {
            "Type": indicator.type,
            "Severity": indicator.severity,
            "Description": indicator.description,
            "Evidence": str(indicator.evidence),
        }
        for indicator in indicators
    ]

    if any_threat:
        for row, indicator in zip(rows, indicators, strict=True):
            row["Threat Lists"] = ", ".join(indicator.threat_lists) if indicator.threat_lists else "-"

    st.dataframe(rows, width="stretch", hide_index=True)

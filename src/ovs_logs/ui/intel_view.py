"""Intelligence tab rendering for the OVS-Log Streamlit dashboard.

Renders locally-computed suspicious indicators (via ``render_analysis_results``)
and saved ``IncidentReport`` records, surfacing their MITRE ATT&CK mappings.
No live threat-intel calls are made from the UI.
"""

from __future__ import annotations

import logging

import duckdb
import streamlit as st

from ovs_logs.core.persistence import ReportStore
from ovs_logs.core.report import IncidentReport, MitreMapping
from ovs_logs.ui.analysis_view import render_analysis_results
from ovs_logs.ui.report_display import report_date_label, severity_label

logger = logging.getLogger(__name__)


def _render_mitre_table(mappings: list[MitreMapping]) -> None:
    if not mappings:
        st.info("No MITRE ATT&CK mappings available for this report.")
        return
    st.dataframe(
        [
            {
                "technique_id": mapping.technique_id,
                "technique_name": mapping.technique_name,
                "tactic": mapping.tactic,
            }
            for mapping in mappings
        ],
        hide_index=True,
    )


def render_intelligence_tab(connection: duckdb.DuckDBPyConnection, table_name: str) -> None:
    """Render the Intelligence tab for ``table_name``.

    Shows suspicious indicators (best-effort) and any saved incident reports
    together with their MITRE ATT&CK mappings.
    """
    render_analysis_results(connection, table_name)

    try:
        reports = ReportStore().get_all_reports(connection)
    except duckdb.Error:
        logger.exception("Failed to load saved reports for intelligence tab")
        st.error("Failed to load saved reports.")
        return

    if not reports:
        st.info("No saved reports.")
        return

    st.subheader("Saved Reports")
    for entry in reports:
        report: IncidentReport = entry["report"]
        with st.expander(f"{report.title} ({report_date_label(entry['created_at'])})", expanded=False):
            st.write(f"**Severity:** {severity_label(report.severity)}")
            st.write(report.summary)
            st.markdown("**MITRE ATT&CK mappings**")
            _render_mitre_table(report.mitre_mappings)

"""Intelligence tab rendering for the OVS-Log Streamlit dashboard.

Delegates report synthesis to :class:`AnalysisService` so the UI shares the
same pipeline as the CLI. Saved reports are still read directly from
:class:`ReportStore` for display.
"""

from __future__ import annotations

import logging
from pathlib import Path

import duckdb
import requests
import streamlit as st

from ovs_logs.config.settings import settings
from ovs_logs.core.analysis.indicators import SuspiciousIndicator
from ovs_logs.core.persistence import ReportStore
from ovs_logs.core.report import IncidentReport, MitreMapping
from ovs_logs.services import AnalysisConfig, AnalysisService
from ovs_logs.ui.analysis_view import compute_indicators, render_analysis_results
from ovs_logs.ui.llm_wiring import LLMConfig
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


def _generate_and_save_report(
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    indicators: list[SuspiciousIndicator],
    *,
    enrich_intel: bool,
) -> None:
    """Synthesize an incident report from ``indicators`` and persist it."""
    if not st.session_state.get("LLM_API_KEY") and not st.session_state.get("LLM_OLLAMA_LOCAL"):
        st.error("Report generation requires an LLM API key. Set it in the sidebar.")
        return

    llm_cfg = LLMConfig(dict(st.session_state))
    config = AnalysisConfig(
        db_path=Path(settings.database.path),
        table=table_name,
        llm=True,
        abuseipdb_api_key=st.session_state.get("ABUSEIPDB_API_KEY"),
        llm_api_key=llm_cfg.api_key,
        llm_endpoint=llm_cfg.resolve_endpoint(),
        llm_model=llm_cfg.resolve_model(),
    )
    service = AnalysisService(config)

    try:
        report_id = service.synthesize_report(connection, indicators, enrich_intel=enrich_intel)
    except (ValueError, requests.exceptions.RequestException):
        logger.exception("LLM synthesis failed for table %s", table_name)
        st.error("LLM synthesis failed. The response was incomplete.")
        return

    st.success(f"Report saved ({report_id})")


def render_intelligence_tab(connection: duckdb.DuckDBPyConnection, table_name: str) -> None:
    """Render the Intelligence tab for ``table_name``.

    Shows suspicious indicators (best-effort) and any saved incident reports
    together with their MITRE ATT&CK mappings. When indicators are present, a
    form lets the user synthesize and persist a new incident report.
    """
    indicators = compute_indicators(connection, table_name)
    render_analysis_results(connection, table_name, indicators=indicators)

    st.divider()
    st.subheader("LLM Report")

    if not indicators:
        st.info("No suspicious indicators found. Analysis must be run before generating a report.")
        return

    with st.form("generate_report_form"):
        col_toggle, col_btn = st.columns([3, 1])
        with col_toggle:
            enrich_intel = st.toggle("Enrich with AbuseIPDB", value=False)
        with col_btn:
            generate_clicked = st.form_submit_button(
                "Generate Report",
                type="primary",
                disabled=not (st.session_state.get("LLM_API_KEY") or st.session_state.get("LLM_OLLAMA_LOCAL")),
            )

    if generate_clicked:
        _generate_and_save_report(connection, table_name, indicators, enrich_intel=enrich_intel)

    try:
        reports = ReportStore().get_all_reports(connection, source_table=table_name)
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

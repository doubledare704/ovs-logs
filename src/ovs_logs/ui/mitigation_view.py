"""Mitigation tab rendering for the OVS-Log Streamlit dashboard.

Surfaces the mitigation artifact of a saved ``IncidentReport`` together with
its MITRE ATT&CK mappings, providing a download for the detection/mitigation
rule. No live threat-intel calls are made from the UI.
"""

from __future__ import annotations

import logging

import duckdb
import streamlit as st

from ovs_logs.core.persistence import ReportStore
from ovs_logs.ui.report_display import report_date_label, severity_label

logger = logging.getLogger(__name__)

_FORMAT_LANGUAGE: dict[str, str] = {"sigma": "yaml", "yara": "yaml", "spl": "spl"}
_EXTENSION: dict[str, str] = {"sigma": "yml", "yara": "yar", "spl": "spl"}
_MIME: dict[str, str] = {"yml": "text/yaml", "yar": "text/plain", "spl": "text/plain"}


def _detect_language(fmt: str) -> str:
    return _FORMAT_LANGUAGE.get(fmt.lower(), "")


def render_mitigation_tab(connection: duckdb.DuckDBPyConnection, table_name: str) -> None:
    """Render the Mitigation tab for ``table_name``.

    Loads saved incident reports and lets the user pick one to view its
    mitigation rule and download it. Saved reports are global and do not
    depend on the currently selected table.
    """
    try:
        reports = ReportStore().get_all_reports(connection)
    except duckdb.Error:
        logger.exception("Failed to load saved reports for mitigation tab")
        st.error("Failed to load saved reports.")
        return

    if not reports:
        st.info("No saved reports available for this table.")
        return

    report_options: dict[str, str] = {
        r["report_id"]: f"{r['report'].title} ({report_date_label(r['created_at'])})" for r in reports
    }
    selected_id = st.selectbox(
        "Select a report",
        options=[r["report_id"] for r in reports],
        format_func=lambda rid: report_options.get(rid, rid),
        key="selected_report_id",
    )

    report = next((r["report"] for r in reports if r["report_id"] == selected_id), None)
    if report is None:
        return

    st.markdown(f"### {report.title} {severity_label(report.severity)}")
    st.write(report.summary)

    st.subheader("MITRE ATT&CK mappings")
    if report.mitre_mappings:
        st.dataframe(
            [
                {
                    "technique_id": mapping.technique_id,
                    "technique_name": mapping.technique_name,
                    "tactic": mapping.tactic,
                    "description": mapping.description,
                }
                for mapping in report.mitre_mappings
            ],
            hide_index=True,
        )
    else:
        st.info("No MITRE ATT&CK mappings available for this report.")

    st.subheader("Mitigation Rule")
    language = _detect_language(report.mitigation.format)
    st.code(report.mitigation.content, language=language)

    ext = _EXTENSION.get(report.mitigation.format.lower(), "txt")
    mime = _MIME.get(ext, "text/plain")
    st.download_button(
        "Download rule",
        data=report.mitigation.content,
        file_name=f"{report.mitigation.format.lower()}_rule.{ext}",
        mime=mime,
    )

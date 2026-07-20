"""Single-page Streamlit dashboard for OVS-Log.

The sidebar, upload pipeline, and ingestion logic have been extracted into
:mod:`ui.components` so each concern can be understood and tested
independently.  This module orchestrates them and renders the four main
tabs (Ingest & Signals, Attack Timeline, Intelligence, Mitigation).
"""

from __future__ import annotations

import logging

import duckdb
import streamlit as st

from ovs_logs.config.settings import settings
from ovs_logs.core.constants import LARGE_FILE_BYTES
from ovs_logs.core.database import Database
from ovs_logs.core.sql_utils import quote_identifier
from ovs_logs.core.validation import SUPPORTED_FORMATS
from ovs_logs.ui.analysis_view import render_analysis_results
from ovs_logs.ui.components.ingest import process_ready_files
from ovs_logs.ui.components.sidebar import render_sidebar
from ovs_logs.ui.components.upload import _format_size, register_uploaded_file, validate_uploaded_file
from ovs_logs.ui.intel_view import render_intelligence_tab
from ovs_logs.ui.mitigation_view import render_mitigation_tab
from ovs_logs.ui.state import SessionKeys
from ovs_logs.ui.timeline_view import render_timeline_card

SK = SessionKeys()

logger = logging.getLogger(__name__)

_ALLOWED_UPLOAD_TYPES: tuple[str, ...] = tuple(sorted(SUPPORTED_FORMATS))


def _initialize_session_state() -> None:
    st.session_state.setdefault(SK.uploaded_files, [])
    st.session_state.setdefault(SK.consumed_uploads, set())


def _render_uploaded_files_overview() -> None:
    uploaded_files = st.session_state[SK.uploaded_files]
    if not uploaded_files:
        st.info("Upload one or more log files to begin ingestion and preview.")
        return

    st.subheader("Uploaded files")
    summary = []
    for file_state in uploaded_files:
        summary.append(
            {
                "Name": file_state["name"],
                "Size": _format_size(file_state["size"]),
                "Format": file_state["format"] or "unknown",
                "Status": file_state["status"],
                "Error": file_state["validation_error"] or "",
            }
        )
    st.table(summary)

    for file_state in uploaded_files:
        with st.expander(f"Raw preview: {file_state['name']}", expanded=False):
            st.write(f"**Status:** {file_state['status']}")
            st.write(f"**Format:** {file_state['format'] or 'unknown'}")
            if file_state["size"] > LARGE_FILE_BYTES:
                st.warning("This is a large upload. Preview is limited to the first 200 lines.")
            if file_state["preview"]:
                st.code(file_state["preview"], language="text")
            elif file_state["status"] == "invalid":
                st.error(file_state["validation_error"])
            else:
                st.info("Preview not available for this file.")


def _render_upload_status_summary() -> None:
    uploaded_files = st.session_state[SK.uploaded_files]
    if not uploaded_files:
        return

    counts = {
        "pending": 0,
        "ready": 0,
        "ingested": 0,
        "invalid": 0,
        "error": 0,
    }
    for file_state in uploaded_files:
        counts[file_state["status"]] += 1

    summary_parts = [
        f"{counts['ready']} ready",
        f"{counts['pending']} pending",
        f"{counts['ingested']} ingested",
    ]
    if counts["invalid"]:
        summary_parts.append(f"{counts['invalid']} invalid")
    if counts["error"]:
        summary_parts.append(f"{counts['error']} error")

    st.info("Upload status: " + ", ".join(summary_parts))


def _render_selected_table(connection: duckdb.DuckDBPyConnection, table_name: str) -> None:
    """Render a data preview (up to 100 rows) of the chosen table."""
    try:
        quoted = quote_identifier(table_name)
        cursor = connection.execute(f"SELECT * FROM {quoted} LIMIT 100")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
    except duckdb.Error:
        st.info(f"Unable to preview table '{table_name}'.")
        return

    if not rows:
        st.info(f"Table '{table_name}' has no rows.")
        return

    st.dataframe([dict(zip(columns, row, strict=True)) for row in rows], hide_index=True)


def _render_ingested_table_preview() -> None:
    ingested_files = [
        file_state for file_state in st.session_state[SK.uploaded_files] if file_state["status"] == "ingested"
    ]
    if not ingested_files:
        return

    st.subheader("Ingested raw table preview")

    normalized_tables = sorted({f["normalized_table"] for f in ingested_files if f.get("normalized_table")})
    if normalized_tables:
        db_path = st.session_state.get(SK.db_path, settings.database.path)
        if db_path:
            st.subheader("Potential signals")
            try:
                with Database(db_path) as connection:
                    for normalized_table in normalized_tables:
                        if len(normalized_tables) > 1:
                            st.caption(f"Table: {normalized_table}")
                        render_analysis_results(connection, normalized_table)
            except (OSError, duckdb.Error) as exc:
                st.error(f"Unable to analyze ingested events: {exc}")

    for file_state in ingested_files:
        with st.expander(f"{file_state['name']} loaded into {file_state['ingest_table']}", expanded=False):
            st.write(f"Row count: {file_state['row_count']}")
            st.write(
                f"Normalized events table: {file_state['normalized_table']} ({file_state['normalized_row_count']} rows)"
            )
            db_path = st.session_state.get(SK.db_path, settings.database.path)
            if db_path and file_state["ingest_table"]:
                try:
                    with Database(db_path) as connection:
                        quoted = quote_identifier(file_state["ingest_table"])
                        sql = f"SELECT * FROM {quoted} LIMIT 100"
                        cursor = connection.execute(sql)
                        rows = cursor.fetchall()
                        columns = [desc[0] for desc in cursor.description]
                        preview_rows = [dict(zip(columns, row, strict=True)) for row in rows]
                        if preview_rows:
                            st.dataframe(preview_rows)
                        else:
                            st.info("No rows in raw table.")
                except (OSError, duckdb.Error) as exc:
                    st.error(f"Unable to preview ingested table: {exc}")


def main() -> None:  # noqa: PLR0912, PLR0915
    """Streamlit entry point for the OVS-Log dashboard."""
    st.set_page_config(page_title="OVS-Log", layout="wide")
    st.title("OVS-Log Dashboard")

    _initialize_session_state()
    render_sidebar()

    db_path = st.session_state.get(SK.db_path, settings.database.path)
    selected_table = st.session_state.get(SK.selected_table)

    tab_ingest, tab_timeline, tab_intel, tab_mit = st.tabs(
        ["Ingest & Signals", "Attack Timeline", "Intelligence", "Mitigation"]
    )

    with tab_ingest:
        st.header("Upload & Ingest Logs")
        uploaded_files = st.file_uploader(
            "Upload log files",
            type=list(_ALLOWED_UPLOAD_TYPES),
            accept_multiple_files=True,
            key=SK.widget_log_file_uploader,
        )

        if uploaded_files:
            for uploaded_file in uploaded_files:
                created, message = register_uploaded_file(uploaded_file)
                if not created and message:
                    st.warning(message)
                elif created and uploaded_file.size > LARGE_FILE_BYTES:
                    st.warning(f"This is a large upload ({_format_size(uploaded_file.size)}). Preview is limited.")

        for file_state in st.session_state[SK.uploaded_files]:
            if file_state["status"] == "pending":
                validate_uploaded_file(file_state)

        _render_upload_status_summary()
        _render_uploaded_files_overview()

        if st.button("Process & Analyze", key=SK.widget_process_ingest):
            process_ready_files(st.session_state.get(SK.db_path, settings.database.path))

        _render_ingested_table_preview()

        ingested_normalized = sorted(
            {
                file_state["normalized_table"]
                for file_state in st.session_state.get(SK.uploaded_files, [])
                if file_state.get("status") == "ingested" and file_state.get("normalized_table")
            }
        )

        if not selected_table:
            st.info("Configure the sidebar to begin analyzing ingested logs.")
        elif not db_path:
            st.info("Set a valid database path in the sidebar to preview and analyze this table.")
        elif selected_table not in ingested_normalized:
            st.subheader(f"Active table: {selected_table}")
            try:
                with Database(db_path) as connection:
                    _render_selected_table(connection, selected_table)
                    st.subheader("Potential signals")
                    render_analysis_results(connection, selected_table)
            except (OSError, duckdb.Error) as exc:
                st.error(f"Unable to analyze table '{selected_table}': {exc}")

    with tab_timeline:
        if not selected_table:
            st.info("Select a table in the sidebar to view its attack timeline.")
        elif not db_path:
            st.info("Set a valid database path in the sidebar to preview and analyze this table.")
        else:
            try:
                with Database(db_path) as connection:
                    st.subheader("Attack Timeline")
                    render_timeline_card(connection, selected_table)
            except (OSError, duckdb.Error) as exc:
                st.error(f"Unable to analyze table '{selected_table}': {exc}")

    with tab_intel:
        if not selected_table:
            st.info("Select a table in the sidebar to view intelligence.")
        elif not db_path:
            st.info("Set a valid database path in the sidebar.")
        else:
            try:
                with Database(db_path) as connection:
                    st.subheader("Intelligence")
                    render_intelligence_tab(connection, selected_table)
            except (OSError, duckdb.Error) as exc:
                st.error(f"Unable to render intelligence for table '{selected_table}': {exc}")

    with tab_mit:
        if not selected_table:
            st.info("Select a table in the sidebar to view mitigations.")
        elif not db_path:
            st.info("Set a valid database path in the sidebar.")
        else:
            try:
                with Database(db_path) as connection:
                    st.subheader("Mitigation")
                    render_mitigation_tab(connection, selected_table)
            except (OSError, duckdb.Error) as exc:
                st.error(f"Unable to render mitigation for table '{selected_table}': {exc}")


if __name__ == "__main__":
    main()

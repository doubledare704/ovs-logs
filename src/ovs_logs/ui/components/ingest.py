"""Ingestion pipeline: file ingestion, batch normalisation, and error handling.

Extracted from the monolithic ``app.py`` so the ingest logic can be
understood and tested independently.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import duckdb
import streamlit as st

from ovs_logs.core.database import Database
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.text_parsing import INGESTION_ADAPTERS
from ovs_logs.core.validation import validate_log_file
from ovs_logs.ui.state import SessionKeys

logger = logging.getLogger(__name__)

SK = SessionKeys()


def _run_batch_normalization(
    connection: duckdb.DuckDBPyConnection,
    ingested_files: list[dict[str, Any]],
) -> None:
    """Run normalization on all successfully ingested files into the unified ``events`` table."""
    tables = [
        (ingested_file["ingest_table"], [name for name, _ in ingested_file["schema"]])
        for ingested_file in ingested_files
        if ingested_file.get("ingest_table") and ingested_file.get("schema")
    ]
    row_count = NormalizationEngine().normalize_batch(connection, tables)
    if row_count:
        for ingested_file in ingested_files:
            ingested_file["normalized_table"] = "events"
            ingested_file["normalized_row_count"] = row_count


def process_ready_files(db_path: str) -> None:
    """Ingest all validated files into DuckDB and normalize them.

    Updates session state file entries with ingestion results (success or
    error).  Errors are rendered as Streamlit error messages so the user
    sees per-file feedback without crashing the dashboard.
    """
    if not db_path:
        st.error("Set a valid database path in the sidebar before ingesting files.")
        return

    ready_files = [file_state for file_state in st.session_state[SK.uploaded_files] if file_state["status"] == "ready"]
    if not ready_files:
        st.warning("No validated uploads are ready for ingestion.")
        return

    errors: list[str] = []
    with st.spinner("Ingesting files into DuckDB and normalizing..."), Database(db_path) as connection:
        for file_state in ready_files:
            try:
                log_file = validate_log_file(file_state["temp_path"])
                adapter = INGESTION_ADAPTERS.get(log_file.format)
                if adapter is None:
                    raise ValueError(f"No ingestion adapter for format '{log_file.format}'")  # noqa: TRY301

                load_result = adapter(log_file, connection)

                file_state["status"] = "ingested"
                file_state["ingest_table"] = load_result.table_name
                file_state["row_count"] = load_result.row_count
                file_state["schema"] = load_result.schema
                file_state["validation_error"] = None
            except (OSError, duckdb.Error, RuntimeError, ValueError) as exc:
                file_state["status"] = "error"
                file_state["validation_error"] = str(exc)
                errors.append(f"{file_state['name']}: {exc}")
            finally:
                Path(file_state["temp_path"]).unlink(missing_ok=True)

        ingested_files = [f for f in ready_files if f["status"] == "ingested"]
        if ingested_files:
            _run_batch_normalization(connection, ingested_files)

    if errors:
        for error in errors:
            st.error(error)
    else:
        st.success("Ingestion and normalization finished successfully.")

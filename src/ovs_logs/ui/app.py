"""Single-page Streamlit dashboard for OVS-Log.

Provides a sidebar with API key inputs, database path configuration, and a
"Recent Tables" navigator that lists user tables from the connected DuckDB
instance. Values entered in the sidebar are persisted in ``st.session_state``
so they remain available to other panels across reruns.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import duckdb
import streamlit as st

if TYPE_CHECKING:
    from streamlit.runtime.uploaded_file_manager import UploadedFile

from ovs_logs.config.settings import settings
from ovs_logs.core.database import Database
from ovs_logs.core.ingestion.adapters import iter_evtx_record_summaries
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.sql_utils import quote_identifier
from ovs_logs.core.text_parsing import ADAPTERS
from ovs_logs.core.validation import SUPPORTED_FORMATS, validate_log_file
from ovs_logs.ui.analysis_view import render_analysis_results
from ovs_logs.ui.intel_view import render_intelligence_tab
from ovs_logs.ui.mitigation_view import render_mitigation_tab
from ovs_logs.ui.timeline_view import render_timeline_card

logger = logging.getLogger(__name__)

_SYSTEM_TABLE_PREFIXES: tuple[str, ...] = (
    "sqlite_",
    "pg_",
    "_ovs_",
)

_SYSTEM_SCHEMAS: tuple[str, ...] = (
    "information_schema",
    "pg_catalog",
)

_ALLOWED_UPLOAD_TYPES: tuple[str, ...] = tuple(sorted(SUPPORTED_FORMATS))


def _on_llm_preset_change() -> None:
    st.session_state.pop("llm_endpoint", None)
    st.session_state.pop("llm_model", None)


_KB = 1024
_MB = 1024 * 1024
_LARGE_FILE_BYTES = 100 * _MB
_MAX_PREVIEW_LINES = 200
_MAX_PREVIEW_BYTES = 64 * _KB


def _read_user_tables(db_path: str) -> list[str]:
    """Return user table names from ``information_schema.tables``.

    System tables (e.g. ``sqlite_*``, anything inside ``information_schema`` or
    ``pg_catalog``) are excluded so the navigator only surfaces application
    tables created by OVS-Log ingestion.
    """
    query = "SELECT table_schema, table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE'"
    with duckdb.connect(database=db_path, read_only=True) as conn:
        rows = conn.execute(query).fetchall()

    table_names: list[str] = []
    for schema, name in rows:
        if schema in _SYSTEM_SCHEMAS:
            continue
        if any(name.startswith(prefix) for prefix in _SYSTEM_TABLE_PREFIXES):
            continue
        table_names.append(name)
    return sorted(table_names)


def _initialize_session_state() -> None:
    st.session_state.setdefault("uploaded_files", [])
    st.session_state.setdefault("consumed_uploads", set())


def _format_size(size: int) -> str:
    if size >= _MB:
        return f"{size / _MB:.1f} MB"
    if size >= _KB:
        return f"{size / _KB:.1f} KB"
    return f"{size} B"


def _save_uploaded_file(uploaded_file: UploadedFile) -> tuple[Path, str]:
    uploaded_file.seek(0)
    suffix = Path(uploaded_file.name).suffix
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix or ".tmp") as tmp:
            temp_path = Path(tmp.name)
            hasher = hashlib.sha256()
            while chunk := uploaded_file.read(8192):
                tmp.write(chunk)
                hasher.update(chunk)
    except OSError:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        raise
    if temp_path is None:
        raise RuntimeError("Failed to create temporary file")
    uploaded_file.seek(0)
    return temp_path, hasher.hexdigest()


def _preview_evtx(path: Path, max_records: int = 50) -> str:
    """Render a short readable summary of EVTX records via the core adapter."""
    try:
        summaries = iter_evtx_record_summaries(path, max_records=max_records)
    except Exception as exc:  # pragma: no cover - exercised through parser errors
        logger.warning("Unable to preview EVTX file %s: %s", path, exc)
        return f"Unable to preview EVTX file: {exc}"

    lines = [
        f"#{summary['record_id']} | {summary['timestamp']} | EventID={summary['event_id']} | "
        f"{summary['provider']} | {summary['channel']}"
        for summary in summaries
    ]
    return "\n".join(lines) if lines else "(no records found)"


def _read_preview_lines(path: Path, max_lines: int = _MAX_PREVIEW_LINES) -> str:
    if path.suffix.lower() == ".evtx":
        return _preview_evtx(path)

    lines: list[bytes] = []
    bytes_read = 0
    with path.open("rb") as fh:
        for _ in range(max_lines):
            remaining = _MAX_PREVIEW_BYTES - bytes_read
            if remaining <= 0:
                break
            line = fh.readline(remaining + 1)
            if not line:
                break
            lines.append(line[:remaining].rstrip(b"\n"))
            bytes_read += min(len(line), remaining)
            if len(line) > remaining:
                break
    return b"\n".join(lines).decode("utf-8", errors="replace")


def _find_uploaded_file(uploaded_files: list[dict[str, Any]], content_hash: str) -> bool:
    return any(file["content_hash"] == content_hash for file in uploaded_files)


def _register_uploaded_file(uploaded_file: UploadedFile) -> tuple[bool, str | None]:
    upload_id = f"{uploaded_file.name}:{uploaded_file.size}"
    if upload_id in st.session_state.get("consumed_uploads", set()):
        return False, None

    uploaded_files = st.session_state["uploaded_files"]
    if any(f["name"] == uploaded_file.name and f["size"] == uploaded_file.size for f in uploaded_files):
        return False, None

    try:
        temp_path, content_hash = _save_uploaded_file(uploaded_file)
    except OSError as exc:
        return False, f"Unable to save upload {uploaded_file.name}: {exc}"

    if _find_uploaded_file(uploaded_files, content_hash):
        temp_path.unlink(missing_ok=True)
        return False, f"Duplicate file skipped: {uploaded_file.name}"

    uploaded_files.append(
        {
            "name": uploaded_file.name,
            "size": uploaded_file.size,
            "content_hash": content_hash,
            "temp_path": str(temp_path),
            "format": None,
            "validated": False,
            "validation_error": None,
            "status": "pending",
            "preview": None,
            "ingest_table": None,
            "row_count": None,
            "schema": None,
            "normalized_table": None,
            "normalized_row_count": None,
        }
    )
    st.session_state.setdefault("consumed_uploads", set()).add(upload_id)
    return True, None


def _validate_uploaded_file(file_state: dict[str, Any]) -> None:
    try:
        log_file = validate_log_file(file_state["temp_path"])
        file_state["format"] = log_file.format
        file_state["validated"] = True
        file_state["validation_error"] = None
        file_state["status"] = "ready"
        file_state["preview"] = _read_preview_lines(Path(file_state["temp_path"]))
    except (OSError, ValueError) as exc:
        Path(file_state["temp_path"]).unlink(missing_ok=True)
        file_state["validated"] = False
        file_state["validation_error"] = str(exc)
        file_state["status"] = "invalid"
        file_state["preview"] = None


def _run_batch_normalization(
    connection: duckdb.DuckDBPyConnection,
    ingested_files: list[dict[str, Any]],
) -> None:
    """Run normalization on all successfully ingested files into the unified ``events`` table.

    Delegates the SQL orchestration to :meth:`NormalizationEngine.normalize_batch`
    so the UI and CLI share a single, append-safe batching path.
    """
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


def _process_ready_files(db_path: str) -> None:
    if not db_path:
        st.error("Set a valid database path in the sidebar before ingesting files.")
        return

    ready_files = [file_state for file_state in st.session_state["uploaded_files"] if file_state["status"] == "ready"]
    if not ready_files:
        st.warning("No validated uploads are ready for ingestion.")
        return

    errors: list[str] = []
    with st.spinner("Ingesting files into DuckDB and normalizing..."), Database(db_path) as connection:
        for file_state in ready_files:
            try:
                log_file = validate_log_file(file_state["temp_path"])
                adapter = ADAPTERS.get(log_file.format)
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


def _render_uploaded_files_overview() -> None:
    uploaded_files = st.session_state["uploaded_files"]
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
            if file_state["size"] > _LARGE_FILE_BYTES:
                st.warning("This is a large upload. Preview is limited to the first 200 lines.")
            if file_state["preview"]:
                st.code(file_state["preview"], language="text")
            elif file_state["status"] == "invalid":
                st.error(file_state["validation_error"])
            else:
                st.info("Preview not available for this file.")


def _render_upload_status_summary() -> None:
    uploaded_files = st.session_state["uploaded_files"]
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
        file_state for file_state in st.session_state["uploaded_files"] if file_state["status"] == "ingested"
    ]
    if not ingested_files:
        return

    st.subheader("Ingested raw table preview")

    normalized_tables = sorted({f["normalized_table"] for f in ingested_files if f.get("normalized_table")})
    if normalized_tables:
        db_path = st.session_state.get("db_path", settings.database.path)
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
            db_path = st.session_state.get("db_path", settings.database.path)
            if db_path and file_state["ingest_table"]:
                try:
                    with Database(db_path) as connection:
                        table_name = file_state["ingest_table"].replace('"', '""')
                        sql = f'SELECT * FROM "{table_name}" LIMIT 100'
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


def render_sidebar() -> None:
    """Render the configuration sidebar and persist state in session_state."""
    st.sidebar.title("OVS-Log Configuration")

    abuseipdb_key = st.sidebar.text_input(
        "AbuseIPDB API Key",
        value=os.getenv("ABUSEIPDB_API_KEY", ""),
        type="password",
        key="abuseipdb_api_key",
        help="Used by the threat intelligence enrichment step.",
    )
    st.session_state["ABUSEIPDB_API_KEY"] = abuseipdb_key

    llm_key = st.sidebar.text_input(
        "LLM API Key",
        value=os.getenv("LLM_API_KEY", ""),
        type="password",
        key="llm_api_key",
        help="Used by the LLM provider to synthesize incident context.",
    )
    st.session_state["LLM_API_KEY"] = llm_key

    st.sidebar.subheader("LLM Configuration")

    preset = st.sidebar.selectbox(
        "Provider preset",
        options=list(settings.LLM_PRESETS.keys()),
        index=list(settings.LLM_PRESETS.keys()).index("OpenAI"),
        key="llm_preset",
        on_change=_on_llm_preset_change,
    )
    preset_cfg = settings.LLM_PRESETS[preset]
    endpoint_default = settings.llm.api_url if preset_cfg.endpoint == "__default__" else preset_cfg.endpoint
    llm_endpoint = st.sidebar.text_input(
        "LLM endpoint",
        value=st.session_state.get("llm_endpoint", endpoint_default),
        key="llm_endpoint",
    )
    model_default = preset_cfg.model or ""
    llm_model = st.sidebar.text_input(
        "LLM model",
        value=st.session_state.get("llm_model", model_default),
        key="llm_model",
    )

    st.session_state["LLM_PRESET"] = preset
    st.session_state["LLM_ENDPOINT"] = llm_endpoint
    st.session_state["LLM_MODEL"] = llm_model

    st.sidebar.subheader("Database")

    db_path = st.sidebar.text_input(
        "Database path",
        value=st.session_state.get("db_path", settings.database.path),
        key="db_path",
        help="Path to the local DuckDB file used for ingestion and analysis.",
    )

    llm_endpoint = st.sidebar.text_input(
        "LLM Endpoint (optional)",
        value=os.getenv("OVS_LOGS_LLM_API_URL", ""),
        key="llm_endpoint",
        help="Override the OpenAI-compatible chat completions endpoint used for report synthesis.",
    )
    st.session_state["LLM_ENDPOINT"] = llm_endpoint or None

    llm_model = st.sidebar.text_input(
        "LLM Model (optional)",
        value=os.getenv("OVS_LOGS_LLM_MODEL", ""),
        key="llm_model",
        help="Override the model name sent to the LLM provider.",
    )
    st.session_state["LLM_MODEL"] = llm_model or None

    st.sidebar.subheader("Recent Tables")

    if not db_path:
        st.sidebar.warning("Provide a database path to list tables.")
        st.session_state.pop("selected_table", None)
        return

    db_file = Path(db_path)
    if not db_file.exists():
        st.sidebar.error(f"Database file not found: {db_path}")
        st.session_state.pop("selected_table", None)
        return

    try:
        tables = _read_user_tables(db_path)
    except duckdb.Error as exc:
        st.sidebar.error(f"Unable to open database: {exc}")
        st.session_state.pop("selected_table", None)
        return
    except OSError as exc:
        st.sidebar.error(f"Unable to access database: {exc}")
        st.session_state.pop("selected_table", None)
        return

    if not tables:
        st.sidebar.info("No application tables found in this database.")
        st.session_state.pop("selected_table", None)
        return

    st.sidebar.selectbox(
        "Select a table",
        options=tables,
        key="selected_table",
    )


def main() -> None:  # noqa: PLR0912, PLR0915
    """Streamlit entry point for the OVS-Log dashboard."""
    st.set_page_config(page_title="OVS-Log", layout="wide")
    st.title("OVS-Log Dashboard")

    _initialize_session_state()
    render_sidebar()

    db_path = st.session_state.get("db_path", settings.database.path)
    selected_table = st.session_state.get("selected_table")

    tab_ingest, tab_timeline, tab_intel, tab_mit = st.tabs(
        ["Ingest & Signals", "Attack Timeline", "Intelligence", "Mitigation"]
    )

    with tab_ingest:
        st.header("Upload & Ingest Logs")
        uploaded_files = st.file_uploader(
            "Upload log files",
            type=list(_ALLOWED_UPLOAD_TYPES),
            accept_multiple_files=True,
            key="log_file_uploader",
        )

        if uploaded_files:
            for uploaded_file in uploaded_files:
                created, message = _register_uploaded_file(uploaded_file)
                if not created and message:
                    st.warning(message)
                elif created and uploaded_file.size > _LARGE_FILE_BYTES:
                    st.warning(f"This is a large upload ({_format_size(uploaded_file.size)}). Preview is limited.")

        for file_state in st.session_state["uploaded_files"]:
            if file_state["status"] == "pending":
                _validate_uploaded_file(file_state)

        _render_upload_status_summary()
        _render_uploaded_files_overview()

        if st.button("Process & Analyze", key="process_ingest"):
            _process_ready_files(st.session_state.get("db_path", settings.database.path))

        _render_ingested_table_preview()

        ingested_normalized = sorted(
            {
                file_state["normalized_table"]
                for file_state in st.session_state.get("uploaded_files", [])
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

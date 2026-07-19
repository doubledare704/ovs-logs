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

from ovs_logs.config.settings import DEFAULT_ENDPOINT_SENTINEL, LLM_PRESETS, settings
from ovs_logs.core.constants import KB, MB
from ovs_logs.core.database import Database
from ovs_logs.core.ingestion.adapters import iter_evtx_record_summaries
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.sql_utils import quote_identifier
from ovs_logs.core.text_parsing import ADAPTERS
from ovs_logs.core.threat_lists import (
    ensure_cache_dir as tl_ensure_cache_dir,
    is_loaded as tl_is_loaded,
    stale_lists as tl_stale_lists,
    update_lists as tl_update_lists,
)
from ovs_logs.core.validation import SUPPORTED_FORMATS, validate_log_file
from ovs_logs.ui.analysis_view import render_analysis_results
from ovs_logs.ui.intel_view import render_intelligence_tab
from ovs_logs.ui.mitigation_view import render_mitigation_tab
from ovs_logs.ui.state import SessionKeys
from ovs_logs.ui.timeline_view import render_timeline_card

SK = SessionKeys()

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
    """Reset endpoint/model to the newly selected preset's defaults.

    Streamlit's ``text_input`` restores its previous widget value from widget
    state even when ``value=`` changes, so the session_state keys must be
    overwritten explicitly to avoid a stale URL (e.g. a bare ``.../api`` host)
    lingering and producing malformed requests.

    Writes to the widget keys (lowercase) so the ``text_input`` widgets pick up
    the preset value.  The application-state keys (uppercase) are populated
    later in ``render_sidebar`` from the widget value.
    """
    preset = st.session_state.get(SK.widget_llm_preset)
    preset_cfg = LLM_PRESETS.get(preset) if preset else None
    if preset_cfg:
        endpoint_default = (
            settings.llm.api_url if preset_cfg.endpoint == DEFAULT_ENDPOINT_SENTINEL else preset_cfg.endpoint
        )
        st.session_state[SK.widget_llm_endpoint] = endpoint_default
        st.session_state[SK.widget_llm_model] = preset_cfg.model or ""


_LARGE_FILE_BYTES = 100 * MB
_MAX_PREVIEW_LINES = 200
_MAX_PREVIEW_BYTES = 64 * KB


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
    st.session_state.setdefault(SK.uploaded_files, [])
    st.session_state.setdefault(SK.consumed_uploads, set())


def _format_size(size: int) -> str:
    if size >= MB:
        return f"{size / MB:.1f} MB"
    if size >= KB:
        return f"{size / KB:.1f} KB"
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
    if upload_id in st.session_state.get(SK.consumed_uploads, set()):
        return False, None

    uploaded_files = st.session_state[SK.uploaded_files]
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
    st.session_state.setdefault(SK.consumed_uploads, set()).add(upload_id)
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

    ready_files = [file_state for file_state in st.session_state[SK.uploaded_files] if file_state["status"] == "ready"]
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
            if file_state["size"] > _LARGE_FILE_BYTES:
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


def _render_sidebar_threat_lists() -> None:  # noqa: PLR0912
    """Render the Threat Lists sidebar section with checkboxes, freshness
    caption, and an update button.

    This section is extracted into its own function to reduce the complexity
    of :func:`render_sidebar`. All state is persisted via ``st.session_state``.
    Errors in threat-list operations are caught gracefully and shown as
    sidebar warnings, never breaking the rest of the UI.
    """
    st.sidebar.subheader("Threat Lists")

    threat_cache_dir = settings.threat_lists.cache_dir
    try:
        tl_ensure_cache_dir(threat_cache_dir)
    except OSError:
        logger.exception("Failed to create threat-list cache dir")
        st.sidebar.warning("Threat list cache directory unavailable")
        return
    default_lists = list(settings.threat_lists.default_lists)
    enabled: list[str] = []
    for list_name in default_lists:
        checked = st.sidebar.checkbox(
            list_name,
            value=True,
            key=f"{SK.widget_threat_list_prefix}{list_name}",
            help=f"Enable matching against {list_name}",
        )
        if checked:
            enabled.append(list_name)
    st.session_state[SK.threat_lists_enabled] = enabled

    # Freshness caption (best-effort, never breaks sidebar)
    try:
        if enabled and tl_is_loaded(enabled, threat_cache_dir):
            stale = tl_stale_lists(
                enabled,
                threat_cache_dir,
                max_age_hours=settings.threat_lists.max_age_hours,
            )
            if stale:
                st.sidebar.caption(f"Stale lists: {', '.join(stale)}")
            else:
                st.sidebar.caption("Threat lists up to date")
        else:
            st.sidebar.caption("Threat lists not yet downloaded")
    except OSError as exc:
        logger.warning("Unable to check threat-list freshness: %s", exc)
        st.sidebar.caption("Threat list cache unavailable")

    if not st.sidebar.button("Update threat lists", key=SK.widget_update_threat_lists):
        return
    if not enabled:
        st.sidebar.warning("Enable at least one threat list first.")
        return
    with st.spinner("Downloading threat lists..."):
        try:
            tl_ensure_cache_dir(threat_cache_dir)
            results = tl_update_lists(
                enabled,
                threat_cache_dir,
                timeout=settings.threat_lists.timeout,
                base_url=settings.threat_lists.base_url,
            )
            cached = [k for k, v in results.items() if v == "cached"]
            errors = [f"{k}: {v}" for k, v in results.items() if v.startswith("error")]
            succeeded = [f"{k}: {v}" for k, v in results.items() if v in ("updated", "unchanged")]
            if cached:
                st.sidebar.warning(f"Offline — using cached data for: {', '.join(cached)}")
            if errors:
                st.sidebar.error("; ".join(errors))
            if succeeded:
                st.sidebar.success("; ".join(succeeded))
        except OSError as exc:
            logger.exception("Failed to update threat lists")
            st.sidebar.error(f"Failed to update threat lists: {exc}")


def render_sidebar() -> None:
    """Render the configuration sidebar and persist state in session_state."""
    st.sidebar.title("OVS-Log Configuration")

    abuseipdb_key = st.sidebar.text_input(
        "AbuseIPDB API Key",
        value=os.getenv("ABUSEIPDB_API_KEY", ""),
        type="password",
        key=SK.widget_abuseipdb_key,
        help="Used by the threat intelligence enrichment step.",
    )
    st.session_state[SK.abuseipdb_api_key] = abuseipdb_key

    llm_key = st.sidebar.text_input(
        "LLM API Key",
        value=os.getenv("LLM_API_KEY", ""),
        type="password",
        key=SK.widget_llm_key,
        help="Used by the LLM provider to synthesize incident context.",
    )
    st.session_state[SK.llm_api_key] = llm_key

    st.sidebar.subheader("LLM Configuration")

    preset_names = list(LLM_PRESETS.keys())
    preset = st.sidebar.selectbox(
        "Provider preset",
        options=preset_names,
        index=preset_names.index("OpenAI"),
        key=SK.widget_llm_preset,
        on_change=_on_llm_preset_change,
    )
    preset_cfg = LLM_PRESETS[preset]
    endpoint_default = settings.llm.api_url if preset_cfg.endpoint == DEFAULT_ENDPOINT_SENTINEL else preset_cfg.endpoint
    if SK.widget_llm_endpoint not in st.session_state:
        st.session_state[SK.widget_llm_endpoint] = endpoint_default
    if SK.widget_llm_model not in st.session_state:
        st.session_state[SK.widget_llm_model] = preset_cfg.model or ""
    llm_endpoint = st.sidebar.text_input(
        "LLM endpoint",
        key=SK.widget_llm_endpoint,
    )
    llm_model = st.sidebar.text_input(
        "LLM model",
        key=SK.widget_llm_model,
    )

    endpoint_value = st.session_state[SK.widget_llm_endpoint]
    _is_ollama = ":11434" in endpoint_value
    st.session_state[SK.llm_ollama_local] = _is_ollama

    st.session_state[SK.llm_preset] = preset
    st.session_state[SK.llm_endpoint] = llm_endpoint
    st.session_state[SK.llm_model] = llm_model

    st.sidebar.subheader("Database")

    db_path = st.sidebar.text_input(
        "Database path",
        value=st.session_state.get(SK.db_path, settings.database.path),
        key=SK.widget_db_path,
        help="Path to the local DuckDB file used for ingestion and analysis.",
    )

    _render_sidebar_threat_lists()

    # ------------------------------------------------------------------ #
    st.sidebar.subheader("Recent Tables")

    if not db_path:
        st.sidebar.warning("Provide a database path to list tables.")
        st.session_state.pop(SK.selected_table, None)
        return

    db_file = Path(db_path)
    if not db_file.exists():
        st.sidebar.error(f"Database file not found: {db_path}")
        st.session_state.pop(SK.selected_table, None)
        return

    try:
        tables = _read_user_tables(db_path)
    except duckdb.Error as exc:
        st.sidebar.error(f"Unable to open database: {exc}")
        st.session_state.pop(SK.selected_table, None)
        return
    except OSError as exc:
        st.sidebar.error(f"Unable to access database: {exc}")
        st.session_state.pop(SK.selected_table, None)
        return

    if not tables:
        st.sidebar.info("No application tables found in this database.")
        st.session_state.pop(SK.selected_table, None)
        return

    st.sidebar.selectbox(
        "Select a table",
        options=tables,
        key=SK.widget_selected_table,
    )


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
                created, message = _register_uploaded_file(uploaded_file)
                if not created and message:
                    st.warning(message)
                elif created and uploaded_file.size > _LARGE_FILE_BYTES:
                    st.warning(f"This is a large upload ({_format_size(uploaded_file.size)}). Preview is limited.")

        for file_state in st.session_state[SK.uploaded_files]:
            if file_state["status"] == "pending":
                _validate_uploaded_file(file_state)

        _render_upload_status_summary()
        _render_uploaded_files_overview()

        if st.button("Process & Analyze", key=SK.widget_process_ingest):
            _process_ready_files(st.session_state.get(SK.db_path, settings.database.path))

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

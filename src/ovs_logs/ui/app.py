"""Single-page Streamlit dashboard for OVS-Log.

Provides a sidebar with API key inputs, database path configuration, and a
"Recent Tables" navigator that lists user tables from the connected DuckDB
instance. Values entered in the sidebar are persisted in ``st.session_state``
so they remain available to other panels across reruns.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any, TYPE_CHECKING

import duckdb
import streamlit as st

if TYPE_CHECKING:
    from streamlit.runtime.uploaded_file_manager import UploadedFile

from ovs_logs.config.settings import settings
from ovs_logs.core.database import Database
from ovs_logs.core.ingestion import adapters
from ovs_logs.core.normalization import NormalizationEngine
from ovs_logs.core.validation import SUPPORTED_FORMATS, validate_log_file

_SYSTEM_TABLE_PREFIXES: tuple[str, ...] = (
    "sqlite_",
    "pg_",
)

_SYSTEM_SCHEMAS: tuple[str, ...] = (
    "information_schema",
    "pg_catalog",
)

_ALLOWED_UPLOAD_TYPES: tuple[str, ...] = tuple(sorted(SUPPORTED_FORMATS))

_LARGE_FILE_BYTES = 100 * 1024 * 1024
_MAX_PREVIEW_LINES = 200
_MAX_PREVIEW_BYTES = 64 * 1024


def _read_user_tables(db_path: str) -> list[str]:
    """Return user table names from ``information_schema.tables``.

    System tables (e.g. ``sqlite_*``, anything inside ``information_schema`` or
    ``pg_catalog``) are excluded so the navigator only surfaces application
    tables created by OVS-Log ingestion.
    """
    query = (
        "SELECT table_schema, table_name "
        "FROM information_schema.tables "
        "WHERE table_type = 'BASE TABLE'"
    )
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
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def _save_uploaded_file(uploaded_file: "UploadedFile") -> tuple[Path, str]:
    uploaded_file.seek(0)
    suffix = Path(uploaded_file.name).suffix
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix or ".tmp")
    temp_path = Path(tmp.name)
    try:
        hasher = hashlib.sha256()
        while chunk := uploaded_file.read(8192):
            tmp.write(chunk)
            hasher.update(chunk)
    except Exception:
        tmp.close()
        temp_path.unlink(missing_ok=True)
        raise
    finally:
        tmp.close()
    uploaded_file.seek(0)
    return temp_path, hasher.hexdigest()


def _read_preview_lines(path: Path, max_lines: int = _MAX_PREVIEW_LINES) -> str:
    if path.suffix.lower() == ".evtx":
        return "EVTX file preview is not available in this UI."

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


def _register_uploaded_file(uploaded_file: "UploadedFile") -> tuple[bool, str | None]:
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


def _get_adapter(format_name: str):
    from typing import Callable

    from ovs_logs.core.ingestion.adapters import LoadResult

    adapter_map: dict[str, Callable[..., LoadResult]] = {
        "csv": adapters.load_csv,
        "json": adapters.load_json,
        "txt": adapters.load_text_log,
        "log": adapters.load_text_log,
        "evtx": adapters.load_evtx,
    }
    return adapter_map.get(format_name)


def _process_ready_files(db_path: str) -> None:
    if not db_path:
        st.error("Set a valid database path in the sidebar before ingesting files.")
        return

    ready_files = [
        file_state
        for file_state in st.session_state["uploaded_files"]
        if file_state["status"] == "ready"
    ]
    if not ready_files:
        st.warning("No validated uploads are ready for ingestion.")
        return

    errors: list[str] = []
    with st.spinner("Ingesting files into DuckDB and normalizing..."):
        with Database(db_path) as connection:
            for file_state in ready_files:
                try:
                    log_file = validate_log_file(file_state["temp_path"])
                    adapter = _get_adapter(log_file.format)
                    if adapter is None:
                        raise ValueError(f"No ingestion adapter for format '{log_file.format}'")

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
                with Database(db_path) as connection:
                    tables_to_union = [f["ingest_table"] for f in ingested_files if f["ingest_table"]]
                    if tables_to_union:
                        union_parts = " UNION ALL ".join(
                            f'SELECT * FROM "{t.replace('"', '""')}"' for t in tables_to_union
                        )
                        connection.execute(f"CREATE OR REPLACE TABLE events AS {union_parts}")
                        
                        row_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                        schema_rows = connection.execute("DESCRIBE events").fetchall()
                        schema = [(row[0], row[1]) for row in schema_rows]
                        
                        for file_state in ingested_files:
                            file_state["normalized_table"] = "events"
                            file_state["normalized_row_count"] = row_count

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
                st.warning(
                    "This is a large upload. Preview is limited to the first 200 lines."
                )
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


def _render_ingested_table_preview() -> None:
    ingested_files = [
        file_state
        for file_state in st.session_state["uploaded_files"]
        if file_state["status"] == "ingested"
    ]
    if not ingested_files:
        return

    st.subheader("Ingested raw table preview")
    for file_state in ingested_files:
        with st.expander(
            f"{file_state['name']} loaded into {file_state['ingest_table']}", expanded=False
        ):
            st.write(f"Row count: {file_state['row_count']}")
            st.write(f"Normalized events table: {file_state['normalized_table']} ({file_state['normalized_row_count']} rows)")
            if file_state["schema"]:
                st.write("**Raw schema:**")
                st.table(
                    [{"column": col, "type": dtype} for col, dtype in file_state["schema"]]
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
                        preview_rows = [dict(zip(columns, row)) for row in rows]
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

    st.sidebar.subheader("Database")

    db_path = st.sidebar.text_input(
        "Database path",
        value=st.session_state.get("db_path", settings.database.path),
        key="db_path",
        help="Path to the local DuckDB file used for ingestion and analysis.",
    )

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


def main() -> None:
    """Streamlit entry point for the OVS-Log dashboard."""
    st.set_page_config(page_title="OVS-Log", layout="wide")
    st.title("OVS-Log Dashboard")

    _initialize_session_state()
    render_sidebar()

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

    selected_table = st.session_state.get("selected_table")
    if selected_table:
        st.write(f"Active table: `{selected_table}`")
    else:
        st.info("Configure the sidebar to begin analyzing ingested logs.")


if __name__ == "__main__":
    main()

"""Single-page Streamlit dashboard for OVS-Log.

Provides a sidebar with API key inputs, database path configuration, and a
"Recent Tables" navigator that lists user tables from the connected DuckDB
instance. Values entered in the sidebar are persisted in ``st.session_state``
so they remain available to other panels across reruns.
"""

from __future__ import annotations

import os
from pathlib import Path

import duckdb
import streamlit as st

from ovs_logs.config.settings import settings

_SYSTEM_TABLE_PREFIXES: tuple[str, ...] = (
    "sqlite_",
    "pg_",
)

_SYSTEM_SCHEMAS: tuple[str, ...] = (
    "information_schema",
    "pg_catalog",
)


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

    default_db_path = st.session_state.get("db_path", settings.database.path)
    st.session_state["db_path"] = default_db_path
    db_path = st.sidebar.text_input(
        "Database path",
        value=default_db_path,
        key="db_path_input",
        help="Path to the local DuckDB file used for ingestion and analysis.",
    )
    st.session_state["db_path"] = db_path

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

    previous = st.session_state.get("selected_table")
    if previous not in tables:
        previous = tables[0]
        st.session_state["selected_table"] = previous

    st.sidebar.selectbox(
        "Select a table",
        options=tables,
        key="selected_table",
    )


def main() -> None:
    """Streamlit entry point for the OVS-Log dashboard."""
    st.set_page_config(page_title="OVS-Log", layout="wide")
    st.title("OVS-Log Dashboard")

    render_sidebar()

    selected_table = st.session_state.get("selected_table")
    if selected_table:
        st.write(f"Active table: `{selected_table}`")
    else:
        st.info("Configure the sidebar to begin analyzing ingested logs.")


if __name__ == "__main__":
    main()

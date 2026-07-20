"""Configuration sidebar for the OVS-Log Streamlit dashboard.

Provides API key inputs, LLM provider presets, threat-list management,
and a "Recent Tables" navigator.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import duckdb
import streamlit as st

from ovs_logs.config import settings as _cfg
from ovs_logs.config.settings import DEFAULT_ENDPOINT_SENTINEL, LLM_PRESETS
from ovs_logs.core.llm import is_ollama_endpoint
from ovs_logs.core.threat_lists import (
    ensure_cache_dir as tl_ensure_cache_dir,
    is_loaded as tl_is_loaded,
    stale_lists as tl_stale_lists,
    update_lists as tl_update_lists,
)
from ovs_logs.ui.state import SessionKeys

logger = logging.getLogger(__name__)

SK = SessionKeys()

_SYSTEM_TABLE_PREFIXES: tuple[str, ...] = (
    "sqlite_",
    "pg_",
    "_ovs_",
)

_SYSTEM_SCHEMAS: tuple[str, ...] = (
    "information_schema",
    "pg_catalog",
)


@st.cache_data(ttl=5)
def _read_user_tables(db_path: str) -> list[str]:
    """Return user table names from ``information_schema.tables``."""
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


def _on_llm_preset_change() -> None:
    """Reset endpoint/model to the newly selected preset's defaults."""
    preset = st.session_state.get(SK.widget_llm_preset)
    preset_cfg = LLM_PRESETS.get(preset) if preset else None
    if preset_cfg:
        endpoint_default = (
            _cfg.settings.llm.api_url if preset_cfg.endpoint == DEFAULT_ENDPOINT_SENTINEL else preset_cfg.endpoint
        )
        st.session_state[SK.widget_llm_endpoint] = endpoint_default
        st.session_state[SK.widget_llm_model] = preset_cfg.model or ""


def _threat_list_freshness_caption(enabled: list[str], cache_dir: str) -> None:
    """Show a sidebar caption with the freshness status of threat lists."""
    try:
        if enabled and tl_is_loaded(enabled, cache_dir):
            stale = tl_stale_lists(
                enabled,
                cache_dir,
                max_age_hours=_cfg.settings.threat_lists.max_age_hours,
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


def _threat_list_download(enabled: list[str], cache_dir: str) -> None:
    """Download or refresh the enabled threat lists, rendering results."""
    if not enabled:
        st.sidebar.warning("Enable at least one threat list first.")
        return
    with st.spinner("Downloading threat lists..."):
        try:
            tl_ensure_cache_dir(cache_dir)
            results = tl_update_lists(
                enabled,
                cache_dir,
                timeout=_cfg.settings.threat_lists.timeout,
                base_url=_cfg.settings.threat_lists.base_url,
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


def _render_sidebar_threat_lists() -> None:
    """Render the Threat Lists sidebar section."""
    st.sidebar.subheader("Threat Lists")

    threat_cache_dir = _cfg.settings.threat_lists.cache_dir
    try:
        tl_ensure_cache_dir(threat_cache_dir)
    except OSError:
        logger.exception("Failed to create threat-list cache dir")
        st.sidebar.warning("Threat list cache directory unavailable")
        return
    default_lists = list(_cfg.settings.threat_lists.default_lists)
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

    _threat_list_freshness_caption(enabled, threat_cache_dir)

    if not st.sidebar.button("Update threat lists", key=SK.widget_update_threat_lists):
        return
    _threat_list_download(enabled, threat_cache_dir)


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
    endpoint_default = (
        _cfg.settings.llm.api_url if preset_cfg.endpoint == DEFAULT_ENDPOINT_SENTINEL else preset_cfg.endpoint
    )
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
    _is_ollama = is_ollama_endpoint(endpoint_value)
    st.session_state[SK.llm_ollama_local] = _is_ollama

    st.session_state[SK.llm_preset] = preset
    st.session_state[SK.llm_endpoint] = llm_endpoint
    st.session_state[SK.llm_model] = llm_model

    st.sidebar.subheader("Database")

    db_path = st.sidebar.text_input(
        "Database path",
        value=st.session_state.get(SK.db_path, _cfg.settings.database.path),
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

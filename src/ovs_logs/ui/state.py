"""Centralised session-state key constants for the Streamlit UI.

All magic-string keys used with ``st.session_state`` are defined here so they
have a single source of truth and can be discovered easily.  Using
``SessionKeys.KEY_NAME`` instead of ``st.session_state[\"key_name\"]`` prevents
typos and makes refactoring safer.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SessionKeys:
    """Well-known key names for ``st.session_state`` entries.

    Attributes prefixed with ``widget_`` correspond to Streamlit widget
    ``key`` parameters (which Streamlit manages automatically).  Plain
    attributes are application-level state set explicitly by the code.
    """

    # ------------------------------------------------------------------ #
    # Upload / ingestion state
    # ------------------------------------------------------------------ #

    uploaded_files: str = "uploaded_files"
    """List[dict]: per-file metadata tracked through the upload→ingest pipeline."""

    consumed_uploads: str = "consumed_uploads"
    """set[str]: upload ids whose files have already been registered (prevents
    double-counting on re-run)."""

    # ------------------------------------------------------------------ #
    # API keys (set from sidebar text_input or env vars)
    # ------------------------------------------------------------------ #

    abuseipdb_api_key: str = "ABUSEIPDB_API_KEY"
    """str: AbuseIPDB API key persisted in session state."""

    llm_api_key: str = "LLM_API_KEY"
    """str: LLM API key persisted in session state."""

    # ------------------------------------------------------------------ #
    # LLM configuration
    # ------------------------------------------------------------------ #

    llm_ollama_local: str = "LLM_OLLAMA_LOCAL"
    """bool: True when the selected LLM endpoint points to a local Ollama instance."""

    llm_preset: str = "LLM_PRESET"
    """str: Name of the selected LLM provider preset."""

    llm_endpoint: str = "LLM_ENDPOINT"
    """str: LLM API endpoint URL."""

    llm_model: str = "LLM_MODEL"
    """str: LLM model name."""

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #

    db_path: str = "db_path"
    """str: Path to the DuckDB database file."""

    selected_table: str = "selected_table"
    """str | None: Table selected in the sidebar navigator."""

    # ------------------------------------------------------------------ #
    # Threat lists
    # ------------------------------------------------------------------ #

    threat_lists_enabled: str = "threat_lists_enabled"
    """list[str]: Names of threat-list files the user has checked in the sidebar."""

    # ------------------------------------------------------------------ #
    # Widget keys (passed as ``key=`` to Streamlit widgets)
    # ------------------------------------------------------------------ #

    widget_abuseipdb_key: str = "abuseipdb_api_key"
    widget_llm_key: str = "llm_api_key"
    widget_llm_endpoint: str = "llm_endpoint"
    widget_llm_model: str = "llm_model"
    widget_llm_preset: str = "llm_preset"
    widget_db_path: str = "db_path"
    widget_selected_table: str = "selected_table"
    widget_log_file_uploader: str = "log_file_uploader"
    widget_process_ingest: str = "process_ingest"
    widget_update_threat_lists: str = "update_threat_lists"
    widget_threat_list_prefix: str = "threat_list_"
    """Prefix for per-list checkboxes; full key is ``threat_list_{name}``."""

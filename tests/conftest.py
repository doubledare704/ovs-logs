"""Shared pytest fixtures and test helpers for OVS-Log.

Fixtures defined here are auto-discovered by pytest. Helper functions must
be imported explicitly by individual test modules.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from pathlib import Path

import duckdb
import pytest
from streamlit.testing.v1 import AppTest
from streamlit.testing.v1.element_tree import Button, Checkbox, Selectbox, TextInput

from ovs_logs.core.analysis.indicators import SuspiciousIndicator
from ovs_logs.core.database import Database
from ovs_logs.core.report import (
    IncidentReport,
    MitigationArtifact,
    MitreMapping,
    TimelineEvent,
)

# ---------------------------------------------------------------------------
# Fixtures (auto-discovered by pytest)
# ---------------------------------------------------------------------------


@pytest.fixture
def db() -> Iterator[duckdb.DuckDBPyConnection]:
    """In-memory DuckDB instance for adapter, analysis, and normalization tests."""
    with Database(":memory:") as conn:
        yield conn


# ---------------------------------------------------------------------------
# Helper functions (import explicitly in test modules)
# ---------------------------------------------------------------------------


def make_db(tmp_path: Path, table_sql: list[tuple[str, str]]) -> Path:
    """Create a temp DuckDB file with the given (name, ddl) user tables."""
    db = tmp_path / "ovs_logs.db"
    with duckdb.connect(str(db)) as conn:
        for name, ddl in table_sql:
            conn.execute(f'CREATE TABLE "{name}" AS {ddl}')
    return db


def selectbox_by_label(at: AppTest, label: str) -> Selectbox:
    """Return the sidebar selectbox whose label matches ``label``.

    The sidebar renders multiple selectboxes (e.g. the LLM provider preset and
    the table navigator). Resolving by label keeps tests robust to sidebar
    ordering changes instead of relying on a hard-coded index.
    """
    try:
        return next(select for select in at.sidebar.selectbox if select.label == label)
    except StopIteration as exc:
        raise AssertionError(f"Sidebar selectbox with label '{label}' not found") from exc


def text_input_by_label(at: AppTest, label: str) -> TextInput:
    """Return the sidebar text input whose label matches ``label``.

    Resolving by label keeps tests robust to sidebar ordering changes instead
    of relying on a hard-coded index.
    """
    try:
        return next(field for field in at.sidebar.text_input if field.label == label)
    except StopIteration as exc:
        raise AssertionError(f"Sidebar text input with label '{label}' not found") from exc


def checkbox_by_label(at: AppTest, label: str) -> Checkbox:
    """Return the sidebar checkbox whose label matches ``label``.

    Resolving by label keeps tests robust to sidebar ordering changes.
    """
    try:
        return next(cb for cb in at.sidebar.checkbox if cb.label == label)
    except StopIteration as exc:
        raise AssertionError(f"Sidebar checkbox with label '{label}' not found") from exc


def sidebar_button_by_label(at: AppTest, label: str) -> Button:
    """Return the sidebar button whose label matches ``label``.

    Resolving by label keeps tests robust to sidebar ordering changes.
    """
    try:
        return next(btn for btn in at.sidebar.button if btn.label == label)
    except StopIteration as exc:
        raise AssertionError(f"Sidebar button with label '{label}' not found") from exc


def button_by_label(at: AppTest, label: str) -> Button:
    """Return the main-page button whose label matches ``label``.

    Resolving by label keeps tests robust to button ordering changes instead
    of relying on a hard-coded index.
    """
    try:
        return next(btn for btn in at.button if btn.label == label)
    except StopIteration as exc:
        raise AssertionError(f"Main-page button with label '{label}' not found") from exc


def make_temp_file(tmp_path: Path, name: str, content: str) -> Path:
    """Write ``content`` to a file at ``tmp_path / name`` and return the path."""
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def schema_columns(schema: Sequence[tuple[str, str]]) -> set[str]:
    """Extract lowercased column names from a DuckDB DESCRIBE result."""
    return {name.lower() for name, _ in schema}


def sample_report() -> IncidentReport:
    """Return a canonical sample ``IncidentReport`` for use in tests."""
    return IncidentReport(
        title="Brute-force login attempt",
        summary="Multiple failed logins from a single IP.",
        severity="High",
        timeline=[
            TimelineEvent(
                timestamp="2024-01-01T00:00:00",
                description="Failed login",
                source_ip="1.2.3.4",
                event_type="POST",
                status_code=401,
            )
        ],
        mitre_mappings=[
            MitreMapping(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                description="Repeated failed authentication attempts.",
            )
        ],
        mitigation=MitigationArtifact(
            format="Sigma",
            title="Detect repeated failed logins",
            content="title: repeated failed logins",
        ),
        indicators=[
            SuspiciousIndicator(
                type="top_talkers",
                severity="High",
                description="IP 1.2.3.4 generated 250 events",
                evidence={"source_ip": "1.2.3.4", "event_count": 250},
            )
        ],
        metadata={"source_file": "auth.log"},
    )

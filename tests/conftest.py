"""Shared pytest fixtures and test helpers for OVS-Log.

Fixtures defined here are auto-discovered by pytest. Helper functions must
be imported explicitly by individual test modules.
"""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Iterator, Sequence
from pathlib import Path

import duckdb
import pytest
from streamlit.testing.v1 import AppTest
from streamlit.testing.v1.element_tree import Button, Checkbox, Selectbox, TextInput

from ovs_logs.config.settings import AbuseIPDBSettings, settings
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


@pytest.fixture(autouse=True)
def _skip_network_tests_offline(request: pytest.FixtureRequest) -> Iterator[None]:
    """Skip ``network``-marked tests when ``OVS_LOGS_OFFLINE`` is set.

    ``network`` tests exercise external-service client code (AbuseIPDB,
    VirusTotal). They are hermetic (HTTP is mocked), but on machines without
    network access they are useless, so ``OVS_LOGS_OFFLINE=1`` opts out of
    running them entirely.
    """
    if "network" in request.node.keywords and os.environ.get("OVS_LOGS_OFFLINE", "").lower() in ("1", "true", "yes"):
        pytest.skip("Network tests disabled (OVS_LOGS_OFFLINE=1)")
    yield


@pytest.fixture
def db() -> Iterator[duckdb.DuckDBPyConnection]:
    """In-memory DuckDB instance for adapter, analysis, and normalization tests."""
    with Database(":memory:") as conn:
        yield conn


@pytest.fixture
def no_threat_intel_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable AbuseIPDB rate limiting and retry backoff for full-pipeline tests.

    UI/CLI tests that exercise the intel path mock the HTTP layer but not the
    *pacing*: ``RateLimiter.wait`` sleeps 1s per request (60 req/min default)
    and the ``retry`` decorator sleeps 1s + 2s of backoff on 429s. Pointing the
    analysis service at zero-rate-limit / zero-retry settings collapses those
    seconds of real ``time.sleep`` while preserving the code paths under test
    (enrichment still succeeds on 200 and degrades gracefully on 429).
    """
    fast_settings = dataclasses.replace(
        settings,
        abuseipdb=AbuseIPDBSettings(max_requests_per_minute=0, max_retries=0, backoff_seconds=0),
    )
    monkeypatch.setattr("ovs_logs.services.analysis_service._default_settings", fast_settings)


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


def launch_app(
    app_path: str | Path,
    db_path: str | Path | None = None,
    table: str | None = None,
    *,
    timeout: float = 10,
    default_timeout: float | None = None,
) -> AppTest:
    """Run the Streamlit app with session_state pre-seeded and return it.

    Seeding ``db_path`` (and optionally the selected ``table``) before the
    first ``.run()`` renders the app fully configured in a single script
    execution. Each ``.run()`` re-executes the entire app script, so the
    conventional run → set db path → select table dance costs three
    executions while the seeded form costs one — a large wall-clock saving
    across the UI test suite.

    Note that this relies on the widget keys ``db_path`` and
    ``selected_table`` intentionally matching the app-state keys of the same
    name (see ``SessionKeys``); pre-seeding breaks if those ever diverge.

    Args:
        app_path: Path to the Streamlit app script.
        db_path: Database path to seed into ``session_state["db_path"]``.
        table: Table name to seed into ``session_state["selected_table"]``.
        timeout: Per-run timeout passed to ``AppTest.run``. Defaults to 10s
            so the single full render (all tabs, table selected) gets the
            same wall-clock budget the old 3-run setup had.
        default_timeout: Optional ``AppTest.from_file`` timeout.
    """
    if default_timeout is None:
        at = AppTest.from_file(str(app_path))
    else:
        at = AppTest.from_file(str(app_path), default_timeout=default_timeout)
    if db_path is not None:
        at.session_state["db_path"] = str(db_path)
    if table is not None:
        at.session_state["selected_table"] = table
    at.run(timeout=timeout)
    return at


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

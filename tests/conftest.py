"""Shared pytest fixtures and test helpers for OVS-Log.

Fixtures defined here are auto-discovered by pytest. Helper functions must
be imported explicitly by individual test modules.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from pathlib import Path

import duckdb
import pytest

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

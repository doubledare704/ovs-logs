"""Project-wide constants for OVS-Log.

Centralises magic strings, numbers, and named tuples that are referenced
across multiple modules so they have a single definition and can be
updated without hunting through source files.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Temporal / time-related constants
# ---------------------------------------------------------------------------

TEMPORAL_BUCKET_INTERVAL: str = "5 minutes"
"""Default time-bucket width for the ``temporal_anomaly`` analysis template."""


# ---------------------------------------------------------------------------
# Text / log parsing constants
# ---------------------------------------------------------------------------

SINGLE_COLUMN_DELIMITER: str = "\x01"
"""Delimiter used by the raw text-log loader to keep each physical line as a
single DuckDB column.  An ASCII ``SOH`` (``\\x01``) is extremely unlikely to
appear in real log files."""


# ---------------------------------------------------------------------------
# Normalized column scheme
# ---------------------------------------------------------------------------

NORMALIZED_COLUMNS: tuple[str, ...] = (
    "event_timestamp",
    "source_ip",
    "event_type",
    "status_code",
    "raw_message",
)
"""The five canonical columns that the analysis engine and templates expect."""


# ---------------------------------------------------------------------------
# EVTX CSV field names
# ---------------------------------------------------------------------------

EVTX_CSV_FIELDNAMES: tuple[str, ...] = (
    "timestamp",
    "event",
    "message",
    "record_id",
    "source_ip",
    "status_code",
    "provider",
    "channel",
    "computer",
    "level",
    "task",
)
"""Column names written to the intermediate CSV when converting EVTX files."""


# ---------------------------------------------------------------------------
# Byte-size helpers
# ---------------------------------------------------------------------------

KB: int = 1024
"""One kilobyte in bytes."""

MB: int = 1024 * 1024
"""One megabyte in bytes."""

LARGE_FILE_BYTES: int = 100 * MB
"""Threshold above which a log file is considered "large" and triggers a
preview-size warning in the UI."""

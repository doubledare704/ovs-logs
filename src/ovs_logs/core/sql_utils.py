"""Shared SQL identifier helpers for DuckDB queries."""

from __future__ import annotations

import re
import uuid

from ovs_logs.core.validation import LogFile

_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
"""Pattern for a valid, unquoted SQL identifier."""

_INVALID_IDENTIFIER_MSG = "Invalid SQL identifier: {!r}"


def quote_identifier(identifier: str) -> str:
    """Quote and validate an identifier safely for DuckDB SQL.

    Validates that the identifier is non-empty and matches the pattern
    ``[a-zA-Z_][a-zA-Z0-9_]*`` before wrapping it in double quotes with
    standard escaping.  Raises ``ValueError`` for empty or unambiguously
    invalid identifiers (e.g. those containing null bytes).

    Note: DuckDB quoted identifiers can technically hold any string, but this
    function intentionally restricts to the common bare-identifier character
    set to catch programmer mistakes early.  For column names sourced from
    ``DESCRIBE`` introspection (which always returns valid identifiers) this
    is safe.
    """
    if not _IDENTIFIER_RE.match(identifier):
        raise ValueError(_INVALID_IDENTIFIER_MSG.format(identifier))
    return '"' + identifier.replace('"', '""') + '"'


def sanitize_table_name(name: str) -> str:
    """Convert a candidate table name into a valid SQL identifier."""
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not safe or safe[0].isdigit():
        safe = f"_{safe}"
    return safe


def resolve_table_name(log_file: LogFile, table_name: str | None) -> str:
    """Generate or validate a table name from a log file.

    If ``table_name`` is provided it is sanitized and returned directly.
    Otherwise a deterministic name is generated from the log file's format
    and stem with a random hex suffix.
    """
    if table_name:
        return sanitize_table_name(table_name)
    stem = sanitize_table_name(log_file.path.stem)
    return f"raw_{log_file.format}_{stem}_{uuid.uuid4().hex[:8]}"


def timestamp_cast_expression(column: str) -> str:
    """Build a best-effort DuckDB expression turning a raw timestamp into UTC TIMESTAMP.

    Handles the common log timestamp shapes (Apache/nginx ``%d/%b/%Y:%H:%M:%S %z``,
    ISO-8601 with offset, syslog ``%b %d %H:%M:%S``, plain ``YYYY-MM-DD HH:MM:SS``,
    ISO, and numeric epoch). Offsets are normalized to UTC so the result is a naive
    ``TIMESTAMP`` regardless of the connection's session time zone. Unparseable input
    yields NULL.

    Note: syslog ``%b %d %H:%M:%S`` carries no year, so DuckDB defaults the year to
    1900. Such timestamps are only reliable for intra-year ordering, not absolute
    dates; supply a year-bearing format upstream when accuracy matters.
    """
    col = quote_identifier(column)
    text = f"CAST({col} AS VARCHAR)"
    return (
        "COALESCE("
        f"try_strptime({text}, '%d/%b/%Y:%H:%M:%S %z') AT TIME ZONE 'UTC',"
        f"try_strptime({text}, '%Y-%m-%dT%H:%M:%S%z') AT TIME ZONE 'UTC',"
        f"try_strptime({text}, '%b %d %H:%M:%S'),"
        f"try_strptime({text}, '%Y-%m-%d %H:%M:%S'),"
        f"try_cast({col} AS TIMESTAMPTZ) AT TIME ZONE 'UTC',"
        f"to_timestamp(try_cast({col} AS BIGINT))"
        ")::TIMESTAMP"
    )

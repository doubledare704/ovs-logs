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

"""Structured text-log parsing for DuckDB ingestion."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import duckdb

from ovs_logs.config.settings import TextParseConfig, settings
from ovs_logs.core.ingestion.adapters import (
    LoadResult,
    load_text_log,
)
from ovs_logs.core.validation import LogFile


def _sanitize_table_name(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not safe or safe[0].isdigit():
        safe = f"_{safe}"
    return safe


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _resolve_table_name(log_file: LogFile, table_name: str | None) -> str:
    if table_name:
        return _sanitize_table_name(table_name)
    return _sanitize_table_name(f"raw_{log_file.format}_{log_file.path.stem}_{uuid.uuid4().hex[:8]}")


def _reload_result(connection: duckdb.DuckDBPyConnection, table_name: str) -> LoadResult:
    quoted = _quote_identifier(table_name)
    row = connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()
    row_count = int(row[0]) if row else 0
    schema_rows = connection.execute(f"DESCRIBE {quoted}").fetchall()
    schema = [(row[0], row[1]) for row in schema_rows]
    return LoadResult(table_name=table_name, row_count=row_count, schema=schema)


def _detect_text_format(path: Path) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            samples = [fh.readline() for _ in range(20)]
        text = "\n".join(samples)
    except OSError:
        return "ambiguous"

    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text, re.MULTILINE) and re.search(r'\[.*?\] "\w+ ', text):
        return "web"
    if re.search(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", text, re.MULTILINE):
        return "syslog"
    if re.search(r'^\s*\{.*"(ts|timestamp)"\s*:', text, re.MULTILINE):
        return "jsonline"
    return "ambiguous"


_STRUCTURED_FIELDS = ("timestamp", "source_ip", "status_code", "event_type")

_STRUCTURED_PATTERNS: dict[str, dict[str, str]] = {
    "web": {
        "timestamp": r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4})\]",
        "source_ip": r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        "status_code": r'"\s+(\d{3})\s+',
        "event_type": r'"(\w+)\s+\S+\s+HTTP',
    },
    "syslog": {
        "timestamp": r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
        "source_ip": r"(?:from\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        "event_type": r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+([A-Za-z0-9_.-]+)(?:\[\d+\])?:",
    },
    "jsonline": {
        "timestamp": r'"(?:ts|timestamp)"\s*:\s*"([^"]+)"',
        "source_ip": r'"(?:src_ip|source_ip|ip)"\s*:\s*"([^"]+)"',
        "status_code": r'"(?:status|status_code)"\s*:\s*(\d+)',
        "event_type": r'"(?:component|event_type|event|method)"\s*:\s*"([^"]+)"',
    },
}


def parse_text_log(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
    *,
    config: TextParseConfig | None = None,
) -> LoadResult:
    """Ingest a text log into DuckDB, with optional structured field extraction.

    When ``config.structured`` is true, the function detects the log format
    from the file content and runs a hybrid regex pass to populate
    ``timestamp``, ``source_ip``, ``status_code``, and ``event_type``. When
    false, the raw table is returned immediately.
    """
    if config is None:
        config = settings.text_parse

    name = _resolve_table_name(log_file, table_name)
    quoted = _quote_identifier(name)

    load_result = load_text_log(log_file, connection, table_name=name)

    if config.max_lines_per_file > 0:
        connection.execute(
            f"CREATE OR REPLACE TABLE {quoted} AS SELECT * FROM {quoted} LIMIT ?",
            [config.max_lines_per_file],
        )
        load_result = _reload_result(connection, name)

    if not config.structured:
        return load_result

    fmt = _detect_text_format(log_file.path)

    if fmt == "ambiguous":
        return load_result

    patterns = _STRUCTURED_PATTERNS.get(fmt)
    if not patterns:
        return load_result

    # Extract structured fields with DuckDB's regexp_extract running multithreaded
    # on columnar data. This replaces the former Python per-line regex loop and
    # the intermediate temp CSV, eliminating a full read+write+read cycle. On no
    # match regexp_extract returns '' automatically, so missing fields stay empty.
    field_exprs: list[str] = []
    params: list[str] = []
    for field in _STRUCTURED_FIELDS:
        pattern = patterns.get(field)
        if pattern:
            field_exprs.append(f"regexp_extract(line, ?, 1) AS {_quote_identifier(field)}")
            params.append(pattern)
        else:
            field_exprs.append(f"'' AS {_quote_identifier(field)}")

    select_sql = ",\n    ".join(field_exprs)
    connection.execute(
        f"CREATE OR REPLACE TABLE {quoted} AS\n"
        f"SELECT\n    {select_sql},\n    line AS raw_message\n"
        f"FROM {quoted}",
        params,
    )

    # Preserve the legacy "no hits -> treat as unstructured" behaviour so the CLI
    # still skips normalization for logs with no extractable structure.
    hit_expr = " OR ".join(f"{_quote_identifier(field)} <> ''" for field in _STRUCTURED_FIELDS)
    hit = connection.execute(
        f"SELECT COUNT_IF({hit_expr}) FROM {quoted}"
    ).fetchone()
    if not hit or hit[0] == 0:
        connection.execute(f"CREATE OR REPLACE TABLE {quoted} AS SELECT line FROM {quoted}")
        return _reload_result(connection, name)

    return _reload_result(connection, name)

"""Structured text-log parsing for DuckDB ingestion."""

from __future__ import annotations

import csv
import os
import re
import tempfile
import uuid
from pathlib import Path

import duckdb

from ovs_logs.core.ingestion.adapters import (
    LoadResult,
    load_text_log,
)
from ovs_logs.core.normalization import NormalizationEngine
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
    stem = _sanitize_table_name(log_file.path.stem)
    return f"raw_{log_file.format}_{stem}_{uuid.uuid4().hex[:8]}"


def _reload_result(connection: duckdb.DuckDBPyConnection, table_name: str) -> LoadResult:
    quoted = _quote_identifier(table_name)
    row = connection.execute(f'SELECT COUNT(*) FROM {quoted}').fetchone()
    row_count = int(row[0]) if row is not None else 0
    schema_rows = connection.execute(f'DESCRIBE {quoted}').fetchall()
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
    if re.search(r'^\s*\{.*"ts"\s*:\s*"', text, re.MULTILINE):
        return "jsonline"
    return "ambiguous"


_WEB_TS_RE = re.compile(r"\[([^\]]+)\]")
_WEB_IP_RE = re.compile(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
_WEB_STATUS_RE = re.compile(r'"\s+(\d{3})\s+')
_WEB_EVENT_RE = re.compile(r'"(\w+)\s+\S+\s+HTTP')

_SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_SYSLOG_IP_RE = re.compile(r"(?:from\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
_SYSLOG_EVENT_RE = re.compile(r"\s+([a-zA-Z_]+?)(?:\[\d+\])?:")

_JSON_TS_RE = re.compile(r'"ts"\s*:\s*"([^"]+)"')
_JSON_IP_RE = re.compile(r'"src_ip"\s*:\s*"([^"]+)"')
_JSON_STATUS_RE = re.compile(r'"status"\s*:\s*(\d+)')
_JSON_EVENT_RE = re.compile(r'"component"\s*:\s*"([^"]+)"')

_AMBIGUOUS_TS_RE = re.compile(r"\[(\d{2}:\d{2}:\d{2})\]")
_AMBIGUOUS_IP_RE = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
_AMBIGUOUS_STATUS_RE = re.compile(r"code=(\d+)")


def _extract_hybrid(text: str, fmt: str) -> dict[str, str]:
    ts = ip = status = event = ""

    if fmt == "web":
        m = _WEB_TS_RE.search(text)
        if m:
            ts = m.group(1)
        m = _WEB_IP_RE.search(text)
        if m:
            ip = m.group(1)
        m = _WEB_STATUS_RE.search(text)
        if m:
            status = m.group(1)
        m = _WEB_EVENT_RE.search(text)
        if m:
            event = m.group(1)

    elif fmt == "syslog":
        m = _SYSLOG_TS_RE.search(text)
        if m:
            ts = m.group(1)
        m = _SYSLOG_IP_RE.search(text)
        if m:
            ip = m.group(1)
        m = _SYSLOG_EVENT_RE.search(text)
        if m:
            event = m.group(1)

    elif fmt == "jsonline":
        m = _JSON_TS_RE.search(text)
        if m:
            ts = m.group(1)
        m = _JSON_IP_RE.search(text)
        if m:
            ip = m.group(1)
        m = _JSON_STATUS_RE.search(text)
        if m:
            status = m.group(1)
        m = _JSON_EVENT_RE.search(text)
        if m:
            event = m.group(1)

    elif fmt == "ambiguous":
        m = _AMBIGUOUS_TS_RE.search(text)
        if m:
            ts = m.group(1)
        m = _AMBIGUOUS_IP_RE.search(text)
        if m:
            ip = m.group(1)
        m = _AMBIGUOUS_STATUS_RE.search(text)
        if m:
            status = m.group(1)
        event = "-".join(text.split()[:2])[:64]

    return {"timestamp": ts, "source_ip": ip, "status_code": status, "event_type": event}


def parse_text_log(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
    structured: bool = True,
) -> LoadResult:
    """Ingest a text log into DuckDB, with optional structured field extraction.

    When ``structured=True``, the function detects the log format from the
    file content and runs a hybrid regex pass to populate ``timestamp``,
    ``source_ip``, ``status_code``, and ``event_type``. When no known
    format matches, or when ``structured=False``, it falls back to the raw
    single-column ``(line VARCHAR)`` table from ``load_text_log``.
    """
    name = _resolve_table_name(log_file, table_name)
    quoted = _quote_identifier(name)

    load_result = load_text_log(log_file, connection, table_name=name)

    if not structured:
        return load_result

    fmt = _detect_text_format(log_file.path)

    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".csv", delete=False, newline=""
        ) as tmp:
            writer = csv.writer(tmp)
            writer.writerow(["timestamp", "source_ip", "status_code", "event_type", "raw_message"])
            raw_rows = connection.execute(f'SELECT line FROM {quoted}').fetchall()
            hit_count = 0
            for (line,) in raw_rows:
                text = line or ""
                fields = _extract_hybrid(text, fmt)
                if any(fields.values()):
                    hit_count += 1
                writer.writerow([
                    fields["timestamp"],
                    fields["source_ip"],
                    fields["status_code"],
                    fields["event_type"],
                    "",
                ])
            tmp_path = tmp.name

        connection.execute(f'DROP TABLE IF EXISTS {quoted}')
        connection.execute(
            f'CREATE OR REPLACE TABLE {quoted} AS '
            f'SELECT * FROM read_csv_auto(?, header=true, delim=\',\', all_varchar=true)',
            [tmp_path],
        )
        return _reload_result(connection, name)
    finally:
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)

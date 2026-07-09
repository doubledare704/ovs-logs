"""Structured text-log parsing for DuckDB ingestion."""

from __future__ import annotations

import csv
import re
import tempfile
import uuid
from collections.abc import Callable
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
    if re.search(
        r'^\s*\{.*"(?:ts|timestamp|time|time_iso8601|time_local|remote_ip|remote_addr|request|response)"\s*:',
        text,
        re.MULTILINE,
    ):
        return "jsonline"
    return "ambiguous"


_WEB_TS_RE = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4})\]")
_WEB_IP_RE = re.compile(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
_WEB_STATUS_RE = re.compile(r'"\s+(\d{3})\s+')
_WEB_EVENT_RE = re.compile(r'"(\w+)\s+\S+\s+HTTP')

_SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_SYSLOG_IP_RE = re.compile(r"(?:from\s+)([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
_SYSLOG_EVENT_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+([A-Za-z0-9_.-]+)(?:\[\d+\])?:")

_JSON_TS_RE = re.compile(r'"(?:ts|timestamp|time|time_iso8601|time_local)"\s*:\s*"([^"]+)"')
_JSON_TS_NUM_RE = re.compile(r'"(?:ts|timestamp|time|time_iso8601|time_local)"\s*:\s*(\d+)')
_JSON_IP_RE = re.compile(r'"(?:src_ip|source_ip|ip|remote_ip|remote_addr)"\s*:\s*"([^"]+)"')
_JSON_STATUS_RE = re.compile(r'"(?:status|status_code|response)"\s*:\s*(\d+)')
_JSON_EVENT_RE = re.compile(r'"(?:component|event_type|event|method|request)"\s*:\s*"([^"]+)"')

_AMBIGUOUS_TS_RE = re.compile(r"\[(\d{2}:\d{2}:\d{2})\]")
_AMBIGUOUS_IP_RE = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
_AMBIGUOUS_STATUS_RE = re.compile(r"code=(\d+)")
_AMBIGUOUS_EVENT_MAX_LENGTH = 64


def _apply_extractors(text: str, patterns: dict[str, re.Pattern[str]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, pattern in patterns.items():
        m = pattern.search(text)
        result[key] = m.group(1) if m else ""
    return result


def _extract_web(text: str) -> dict[str, str]:
    return _apply_extractors(
        text,
        {
            "timestamp": _WEB_TS_RE,
            "source_ip": _WEB_IP_RE,
            "status_code": _WEB_STATUS_RE,
            "event_type": _WEB_EVENT_RE,
        },
    )


def _extract_syslog(text: str) -> dict[str, str]:
    base = _apply_extractors(
        text,
        {
            "timestamp": _SYSLOG_TS_RE,
            "source_ip": _SYSLOG_IP_RE,
            "event_type": _SYSLOG_EVENT_RE,
        },
    )
    base["status_code"] = ""
    return base


def _extract_jsonline(text: str) -> dict[str, str]:
    fields = _apply_extractors(
        text,
        {
            "timestamp": _JSON_TS_RE,
            "source_ip": _JSON_IP_RE,
            "status_code": _JSON_STATUS_RE,
            "event_type": _JSON_EVENT_RE,
        },
    )
    if not fields.get("timestamp"):
        num_match = _JSON_TS_NUM_RE.search(text)
        if num_match:
            fields["timestamp"] = num_match.group(1)
    event_type = fields.get("event_type")
    if event_type and " " in event_type:
        fields["event_type"] = event_type.split()[0]
    return fields


def _extract_ambiguous(text: str) -> dict[str, str]:
    ts = ip = status = ""
    m = _AMBIGUOUS_TS_RE.search(text)
    if m:
        ts = m.group(1)
    m = _AMBIGUOUS_IP_RE.search(text)
    if m:
        ip = m.group(1)
    m = _AMBIGUOUS_STATUS_RE.search(text)
    if m:
        status = m.group(1)
    event = "-".join(text.split()[:2])
    if len(event) > _AMBIGUOUS_EVENT_MAX_LENGTH:
        event = event[: _AMBIGUOUS_EVENT_MAX_LENGTH - 3] + "..."
    return {"timestamp": ts, "source_ip": ip, "status_code": status, "event_type": event}


_FORMAT_EXTRACTORS: dict[str, Callable[[str], dict[str, str]]] = {
    "web": _extract_web,
    "syslog": _extract_syslog,
    "jsonline": _extract_jsonline,
    "ambiguous": _extract_ambiguous,
}


def _extract_hybrid(text: str, fmt: str) -> dict[str, str]:
    extractor = _FORMAT_EXTRACTORS.get(fmt)
    if extractor is None:
        return {"timestamp": "", "source_ip": "", "status_code": "", "event_type": ""}
    return extractor(text)


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

    tmp_path: str | None = None
    hit_count = 0
    try:
        # Heuristic: only inspect the first 20 lines for format detection.
        # This keeps detection cheap but may misclassify logs with long headers.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".csv", delete=False, newline="") as tmp:
            tmp_path = tmp.name
            writer = csv.writer(tmp)
            writer.writerow(["timestamp", "source_ip", "status_code", "event_type", "raw_message"])
            cursor = connection.execute(f"SELECT line FROM {quoted}")
            while rows := cursor.fetchmany(10_000):
                for (line,) in rows:
                    text = line or ""
                    fields = _extract_hybrid(text, fmt)
                    if any(fields[k] for k in ("timestamp", "source_ip", "status_code", "event_type")):
                        hit_count += 1
                    writer.writerow(
                        [
                            fields["timestamp"],
                            fields["source_ip"],
                            fields["status_code"],
                            fields["event_type"],
                            text,
                        ]
                    )

        if hit_count == 0:
            return load_result

        connection.execute(
            f"CREATE OR REPLACE TABLE {quoted} AS SELECT * "
            "FROM read_csv_auto(?, header=true, delim=',', all_varchar=true)",
            [tmp_path],
        )
        result = _reload_result(connection, name)
        return result
    finally:
        if tmp_path is not None and Path(tmp_path).exists():
            Path(tmp_path).unlink()

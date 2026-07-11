"""Structured text-log parsing for DuckDB ingestion."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

import duckdb

from ovs_logs.config.settings import TextParseConfig, settings
from ovs_logs.core.ingestion.adapters import (
    LoadResult,
    build_result,
    load_csv,
    load_evtx,
    load_json,
    load_text_log,
)
from ovs_logs.core.sql_utils import quote_identifier, resolve_table_name
from ovs_logs.core.validation import LogFile


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

_JSON_TS_KEYS = ("ts", "timestamp", "time", "time_iso8601", "time_local")
_JSON_IP_KEYS = ("src_ip", "source_ip", "ip", "remote_ip", "remote_addr")
_JSON_STATUS_KEYS = ("status", "status_code", "response")
_JSON_EVENT_KEYS = ("component", "event_type", "event", "method", "request")


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
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {"timestamp": "", "source_ip": "", "status_code": "", "event_type": ""}
    if not isinstance(obj, dict):
        return {"timestamp": "", "source_ip": "", "status_code": "", "event_type": ""}

    def _first(keys: tuple[str, ...]) -> str:
        for key in keys:
            if key in obj and obj[key] is not None:
                return str(obj[key])
        return ""

    event_type = _first(_JSON_EVENT_KEYS)
    if event_type and " " in event_type:
        event_type = event_type.split()[0]
    return {
        "timestamp": _first(_JSON_TS_KEYS),
        "source_ip": _first(_JSON_IP_KEYS),
        "status_code": _first(_JSON_STATUS_KEYS),
        "event_type": event_type,
    }


_FORMAT_EXTRACTORS: dict[str, Callable[[str], dict[str, str]]] = {
    "web": _extract_web,
    "syslog": _extract_syslog,
    "jsonline": _extract_jsonline,
}


def _extract_hybrid(text: str, fmt: str) -> dict[str, str]:
    extractor = _FORMAT_EXTRACTORS.get(fmt)
    if extractor is None:
        return {"timestamp": "", "source_ip": "", "status_code": "", "event_type": ""}
    return extractor(text)


def _build_structured_select_clause(fmt: str) -> str:
    """Build a SELECT clause for structured text parsing in DuckDB SQL."""
    extractor_map = {
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
    }

    patterns = extractor_map.get(fmt, {})
    select_parts = []
    for field, pattern in patterns.items():
        if field == "timestamp":
            select_parts.append(f"regexp_extract(line, '{pattern}', 1) AS timestamp")
        elif field == "source_ip":
            select_parts.append(f"regexp_extract(line, '{pattern}', 1) AS source_ip")
        elif field == "status_code":
            select_parts.append(f"CAST(regexp_extract(line, '{pattern}', 1) AS VARCHAR) AS status_code")
        elif field == "event_type":
            select_parts.append(f"regexp_extract(line, '{pattern}', 1) AS event_type")

    if "timestamp" not in patterns:
        select_parts.append("NULL AS timestamp")
    if "source_ip" not in patterns:
        select_parts.append("NULL AS source_ip")
    if "status_code" not in patterns:
        select_parts.append("NULL AS status_code")
    if "event_type" not in patterns:
        select_parts.append("NULL AS event_type")

    select_parts.append("line AS raw_message")
    return ", ".join(select_parts)


def _build_jsonline_select_clause() -> str:
    """Build a SELECT clause for JSON-line parsing in DuckDB SQL."""
    ts_pattern = r'"(?:ts|timestamp|time|time_iso8601|time_local)"\s*:\s*"([^"]+)"'
    ts_epoch_pattern = r'"(?:ts|timestamp|time|time_iso8601|time_local)"\s*:\s*(\d+)'
    ts_quoted = f"regexp_extract(line, '{ts_pattern}', 1)"
    ts_epoch = f"CAST(regexp_extract(line, '{ts_epoch_pattern}', 1) AS VARCHAR)"
    ts_expr = f"COALESCE(NULLIF({ts_quoted}, ''), {ts_epoch})"
    ip_pattern = r'"(?:src_ip|source_ip|ip|remote_ip|remote_addr)"\s*:\s*"([^"]+)"'
    status_pattern = r'"(?:status|status_code|response)"\s*:\s*(\d+)'
    event_pattern = r'"(?:component|event_type|event|method|request)"\s*:\s*"([^"]+)"'

    ip_expr = f"regexp_extract(line, '{ip_pattern}', 1)"
    status_expr = f"CAST(regexp_extract(line, '{status_pattern}', 1) AS VARCHAR)"
    event_raw = f"regexp_extract(line, '{event_pattern}', 1)"
    event_expr = f"regexp_extract({event_raw}, '(\\w+)', 1)"

    return (
        f"{ts_expr} AS timestamp, "
        f"{ip_expr} AS source_ip, "
        f"{status_expr} AS status_code, "
        f"{event_expr} AS event_type, "
        "line AS raw_message"
    )


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

    name = resolve_table_name(log_file, table_name)
    quoted = quote_identifier(name)

    load_result = load_text_log(log_file, connection, table_name=name)

    if config.max_lines_per_file > 0:
        connection.execute(
            f"CREATE OR REPLACE TABLE {quoted} AS SELECT * FROM {quoted} LIMIT ?",
            [config.max_lines_per_file],
        )
        load_result = build_result(connection, name)

    if not config.structured:
        return load_result

    fmt = _detect_text_format(log_file.path)

    if fmt not in ("web", "syslog", "jsonline"):
        return load_result

    select_clause = _build_jsonline_select_clause() if fmt == "jsonline" else _build_structured_select_clause(fmt)

    connection.execute(f"CREATE OR REPLACE TABLE {quoted} AS SELECT {select_clause} FROM {quoted}")

    row = connection.execute(
        f"SELECT COUNT(*) FROM {quoted} WHERE timestamp <> '' OR source_ip <> '' OR event_type <> ''"
    ).fetchone()
    hit_count = int(row[0]) if row else 0

    if hit_count == 0:
        return load_result

    return build_result(connection, name)


def ingest_text_log_structured(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Ingest a text log with structured parsing, falling back to raw on failure.

    Attempts ``parse_text_log`` first. If the format detection or structured
    extraction raises ``ValueError``, falls back to ``load_text_log`` for a
    single-column raw table.
    """
    try:
        return parse_text_log(log_file, connection, table_name=table_name)
    except ValueError:
        return load_text_log(log_file, connection, table_name=table_name)


ADAPTERS: dict[str, Callable[..., LoadResult]] = {
    "csv": load_csv,
    "json": load_json,
    "evtx": load_evtx,
    "txt": ingest_text_log_structured,
    "log": ingest_text_log_structured,
}

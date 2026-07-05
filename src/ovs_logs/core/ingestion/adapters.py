"""DuckDB ingestion adapters for supported log formats."""

from __future__ import annotations

import csv
import json
import logging
import re
import tempfile
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb

try:
    from evtx import PyEvtxParser
except ImportError:  # pragma: no cover - depends on optional runtime dependency
    PyEvtxParser: type | None = None  # type: ignore[assignment]

from ovs_logs.core.validation import LogFile


@dataclass(frozen=True)
class LoadResult:
    """Metadata returned after a successful ingestion."""

    table_name: str
    row_count: int
    schema: Sequence[tuple[str, str]]


def _sanitize_table_name(name: str) -> str:
    """Convert a candidate table name into a valid SQL identifier."""
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not safe or safe[0].isdigit():
        safe = f"_{safe}"
    return safe


def _generate_table_name(log_file: LogFile) -> str:
    """Create a deterministic table name from a validated log file."""
    stem = _sanitize_table_name(log_file.path.stem)
    return f"raw_{log_file.format}_{stem}_{uuid.uuid4().hex[:8]}"


def _resolve_table_name(log_file: LogFile, table_name: str | None) -> str:
    return _sanitize_table_name(table_name) if table_name else _generate_table_name(log_file)


def _quote_identifier(identifier: str) -> str:
    """Quote an identifier safely for DuckDB SQL."""
    return '"' + identifier.replace('"', '""') + '"'


def _build_result(connection: duckdb.DuckDBPyConnection, table_name: str) -> LoadResult:
    """Query the loaded table for row count and schema."""
    quoted_name = _quote_identifier(table_name)
    row = connection.execute(f"SELECT COUNT(*) FROM {quoted_name}").fetchone()
    row_count = row[0] if row is not None else 0
    schema_rows = connection.execute(f"DESCRIBE {quoted_name}").fetchall()
    schema = [(row[0], row[1]) for row in schema_rows]
    return LoadResult(table_name=table_name, row_count=row_count, schema=schema)


def load_csv(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Load a CSV file into DuckDB using ``read_csv_auto``."""
    name = _resolve_table_name(log_file, table_name)
    quoted_name = _quote_identifier(name)
    connection.execute(
        f"CREATE OR REPLACE TABLE {quoted_name} AS SELECT * "
        "FROM read_csv_auto(?, header=true, delim=',', all_varchar=true)",
        [str(log_file.path.resolve())],
    )
    return _build_result(connection, name)


def load_json(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Load a JSON file into DuckDB using ``read_json_auto``."""
    name = _resolve_table_name(log_file, table_name)
    quoted_name = _quote_identifier(name)
    connection.execute(
        f"CREATE OR REPLACE TABLE {quoted_name} AS SELECT * FROM read_json_auto(?)",
        [str(log_file.path.resolve())],
    )
    return _build_result(connection, name)


def load_text_log(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
    batch_size: int = 1000,
) -> LoadResult:
    """Load an unstructured text or log file into a single-column DuckDB table."""
    name = _resolve_table_name(log_file, table_name)
    quoted_name = _quote_identifier(name)
    connection.execute(f"CREATE OR REPLACE TABLE {quoted_name} (line VARCHAR)")
    logging.info("Loading text log into table %s from %s", name, log_file.path)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".csv", delete=False, newline="") as tmp:
            writer = csv.writer(tmp)
            writer.writerow(["line"])
            with log_file.path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    writer.writerow([line.rstrip("\n")])
            tmp_path = tmp.name
            logging.info("Temporary CSV file created at %s for ingestion", tmp_path)

        logging.info("Inserting data from temporary CSV into table %s", name)
        connection.execute(
            f"INSERT INTO {quoted_name} SELECT * FROM read_csv_auto(?, header=true, delim=',', all_varchar=true)",
            [tmp_path],
        )
    finally:
        if tmp_path is not None and Path(tmp_path).exists():
            Path(tmp_path).unlink()

    return _build_result(connection, name)


def _flatten_event_payload(value: Any, parent_key: str = "") -> dict[str, Any]:
    """Recursively flatten a nested mapping into a dotted-key dictionary."""
    if isinstance(value, dict):
        flattened: dict[str, Any] = {}
        for key, nested_value in value.items():
            next_key = f"{parent_key}_{key}" if parent_key else str(key)
            flattened.update(_flatten_event_payload(nested_value, next_key))
        return flattened

    if isinstance(value, list):
        return {parent_key: value} if parent_key else {}

    return {parent_key: value} if parent_key else {}


def _extract_evtx_fields(event_data: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """Create a flat row from parsed EVTX data and parser metadata."""
    flattened = _flatten_event_payload(event_data)

    timestamp = None
    for key in ("System_TimeCreated_SystemTime", "TimeCreated_SystemTime", "timestamp"):
        if key in flattened and flattened[key] not in (None, ""):
            timestamp = flattened[key]
            break
    if timestamp is None:
        timestamp = record.get("timestamp")

    event_id = None
    for key in ("System_EventID", "EventID"):
        if key in flattened and flattened[key] not in (None, ""):
            event_id = flattened[key]
            break

    source_ip = None
    for key in (
        "System_EventData_IpAddress",
        "EventData_IpAddress",
        "IpAddress",
        "ClientIpAddress",
        "SourceIp",
    ):
        if key in flattened and flattened[key] not in (None, ""):
            source_ip = flattened[key]
            break

    status_code = None
    for key in ("System_EventData_StatusCode", "EventData_StatusCode", "StatusCode", "Status"):
        if key in flattened and flattened[key] not in (None, ""):
            status_code = flattened[key]
            break

    message = json.dumps(flattened, ensure_ascii=False, sort_keys=True)

    row: dict[str, Any] = {
        "timestamp": timestamp,
        "event": event_id,
        "message": message,
        "record_id": record.get("identifier"),
    }
    if source_ip is not None:
        row["source_ip"] = source_ip
    if status_code is not None:
        row["status_code"] = status_code
    return row


def load_evtx(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Convert an EVTX file into a temporary CSV and load it into DuckDB."""
    if PyEvtxParser is None:  # pragma: no cover - depends on optional runtime dependency
        raise RuntimeError("EVTX support requires the optional 'evtx' dependency to be installed.")

    name = _resolve_table_name(log_file, table_name)
    tmp_path: str | None = None

    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".csv", delete=False, newline="") as tmp:
            tmp_path = tmp.name
            writer = csv.DictWriter(
                tmp,
                fieldnames=["timestamp", "event", "message", "record_id", "source_ip", "status_code"],
                extrasaction="ignore",
            )
            writer.writeheader()

            parser = PyEvtxParser(str(log_file.path.resolve()))
            try:
                records = parser.records_json()
                for record in records:
                    if record is None:
                        continue
                    payload = record.get("data")
                    if isinstance(payload, str):
                        try:
                            event_data: dict[str, Any] = json.loads(payload)
                        except json.JSONDecodeError as exc:
                            raise RuntimeError(f"Unable to parse EVTX record {record.get('identifier')}") from exc
                    elif isinstance(payload, dict):
                        event_data = payload
                    else:
                        event_data = {"raw": payload}

                    if "Event" in event_data and set(event_data.keys()) == {"Event"}:
                        event_data = event_data["Event"]

                    row = _extract_evtx_fields(event_data, record)
                    writer.writerow(row)
            except RuntimeError as exc:
                if "Unable to parse EVTX record" in str(exc):
                    raise
                raise RuntimeError(f"Unable to parse EVTX file {log_file.path}") from exc
            except Exception as exc:  # pragma: no cover - exercised through parser errors
                raise RuntimeError(f"Unable to parse EVTX file {log_file.path}") from exc

        connection.execute(
            f'CREATE OR REPLACE TABLE "{name}" AS SELECT * FROM read_csv_auto(?)',
            [tmp_path],
        )
    finally:
        if tmp_path is not None and Path(tmp_path).exists():
            Path(tmp_path).unlink()

    return _build_result(connection, name)

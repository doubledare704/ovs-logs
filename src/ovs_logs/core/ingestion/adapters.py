"""DuckDB ingestion adapters for supported log formats."""

from __future__ import annotations

import csv
import json
import logging
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
from evtx import PyEvtxParser

from ovs_logs.core.constants import EVTX_CSV_FIELDNAMES, SINGLE_COLUMN_DELIMITER
from ovs_logs.core.sql_utils import quote_identifier, resolve_table_name
from ovs_logs.core.validation import LogFile


@dataclass(frozen=True)
class LoadResult:
    """Metadata returned after a successful ingestion."""

    table_name: str
    row_count: int
    schema: Sequence[tuple[str, str]]

    @property
    def is_unstructured(self) -> bool:
        """Return True if the ingested table contains raw unstructured text."""
        return len(self.schema) == 1 and self.schema[0][0] == "line"


def build_result(connection: duckdb.DuckDBPyConnection, table_name: str) -> LoadResult:
    """Query the loaded table for row count and schema."""
    quoted_name = quote_identifier(table_name)
    row = connection.execute(f"SELECT COUNT(*) FROM {quoted_name}").fetchone()
    row_count = int(row[0]) if row is not None else 0
    schema_rows = connection.execute(f"DESCRIBE {quoted_name}").fetchall()
    schema = [(row[0], row[1]) for row in schema_rows]
    return LoadResult(table_name=table_name, row_count=row_count, schema=schema)


def load_csv(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Load a CSV file into DuckDB using ``read_csv_auto``."""
    name = resolve_table_name(log_file, table_name)
    quoted_name = quote_identifier(name)
    connection.execute(
        f"CREATE OR REPLACE TABLE {quoted_name} AS SELECT * "
        "FROM read_csv_auto(?, header=true, delim=',', all_varchar=true)",
        [str(log_file.path.resolve())],
    )
    return build_result(connection, name)


def load_json(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Load a JSON file into DuckDB using ``read_json_auto``."""
    name = resolve_table_name(log_file, table_name)
    quoted_name = quote_identifier(name)
    connection.execute(
        f"CREATE OR REPLACE TABLE {quoted_name} AS SELECT * FROM read_json_auto(?)",
        [str(log_file.path.resolve())],
    )
    return build_result(connection, name)


def load_text_log(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Load an unstructured text or log file into a single-column DuckDB table.

    DuckDB reads the source file directly into a ``line`` column in parallel C++,
    replacing the former slow Python line-by-line copy through an intermediate
    temp CSV. A single-column schema with an unlikely delimiter and disabled
    quoting preserves each physical line verbatim even when it contains commas
    or quotes.
    """
    name = resolve_table_name(log_file, table_name)
    quoted_name = quote_identifier(name)
    logging.info("Loading text log into table %s from %s", name, log_file.path)
    connection.execute(
        f"CREATE OR REPLACE TABLE {quoted_name} AS "
        "SELECT CAST(col1 AS VARCHAR) AS line FROM read_csv(?, header=false, "
        f"all_varchar=true, columns={{'col1': 'VARCHAR'}}, delim='{SINGLE_COLUMN_DELIMITER}', quote='', escape='')",
        [str(log_file.path.resolve())],
    )
    return build_result(connection, name)


def _is_xml_node(value: Any) -> bool:
    """Return True when a dict uses the pyevtx-rs XML-JSON node shape.

    Real ``evtx`` records nest XML attributes under ``#attributes`` and text
    under ``#text``. Such nodes must be unwrapped rather than recursed into.
    """
    return isinstance(value, dict) and ("#text" in value or "#attributes" in value)


def _flatten_named_data_list(value: list[Any]) -> dict[str, Any] | None:
    """Collapse an EventData ``Data`` array into ``{Name: text}`` pairs.

    pyevtx-rs renders ``<Data Name="IpAddress">1.2.3.4</Data>`` as
    ``{"#attributes": {"Name": "IpAddress"}, "#text": "1.2.3.4"}``. Returns
    ``None`` when the list does not follow this shape so it is preserved
    verbatim (e.g. a list of plain scalar values).
    """
    if not value:
        return None
    named: dict[str, Any] = {}
    for item in value:
        if not isinstance(item, dict):
            return None
        attributes = item.get("#attributes")
        if not isinstance(attributes, dict) or "Name" not in attributes:
            return None
        text = item.get("#text")
        named[attributes["Name"]] = text
    return named


def _flatten_xml_node(node: dict[str, Any], parent_key: str) -> dict[str, Any]:
    """Unwrap a single XML-JSON node into dotted keys.

    ``#text`` collapses to the parent key's value, while ``#attributes``
    children are hoisted to ``parent_<attr>`` keys. ``@``-prefixed attribute
    names (an alternate convention) have the prefix stripped. When the node
    is at the top level (no ``parent_key``), its ``#text`` is preserved under
    a ``"#text"`` key rather than being silently dropped.
    """
    result: dict[str, Any] = {}
    if "#text" in node:
        result[parent_key if parent_key else "#text"] = node["#text"]
    attributes = node.get("#attributes")
    if isinstance(attributes, dict):
        for attr_key, attr_value in attributes.items():
            clean = attr_key[1:] if attr_key.startswith("@") else attr_key
            next_key = f"{parent_key}_{clean}" if parent_key else clean
            result[next_key] = attr_value
    return result


def _flatten_event_payload(value: Any, parent_key: str = "") -> dict[str, Any]:
    """Recursively flatten a nested mapping into a dotted-key dictionary.

    XML-JSON nodes (``#text`` / ``#attributes``) are unwrapped and named
    ``Data`` arrays are collapsed into ``parent_<Name>`` keys so that
    EVTX fields such as ``System_TimeCreated_SystemTime`` resolve correctly.
    """
    if isinstance(value, list):
        named = _flatten_named_data_list(value)
        if named is not None:
            if not parent_key:
                return named
            return {f"{parent_key}_{name}": item for name, item in named.items()}
        return {parent_key: value} if parent_key else {}

    if isinstance(value, dict):
        flattened: dict[str, Any] = {}
        if "#text" in value:
            flattened[parent_key if parent_key else "#text"] = value["#text"]
        attributes = value.get("#attributes")
        if isinstance(attributes, dict):
            for attr_key, attr_value in attributes.items():
                clean = attr_key[1:] if attr_key.startswith("@") else attr_key
                next_key = f"{parent_key}_{clean}" if parent_key else clean
                flattened[next_key] = attr_value

        for key, nested_value in value.items():
            if key in ("#text", "#attributes"):
                continue
            next_key = f"{parent_key}_{key}" if parent_key else str(key)
            flattened.update(_flatten_event_payload(nested_value, next_key))
        return flattened

    return {parent_key: value} if parent_key else {}


def _first_non_empty(flattened: dict[str, Any], keys: Sequence[str]) -> Any:
    """Return the first non-empty value among ``keys``, or ``None``."""
    return next(
        (flattened[key] for key in keys if key in flattened and flattened[key] not in (None, "")),
        None,
    )


def _extract_evtx_fields(event_data: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """Create a flat row from parsed EVTX data and parser metadata."""
    flattened = _flatten_event_payload(event_data)

    timestamp = _first_non_empty(flattened, ("System_TimeCreated_SystemTime", "TimeCreated_SystemTime", "timestamp"))
    if timestamp is None:
        timestamp = record.get("timestamp")

    event_id = _first_non_empty(flattened, ("System_EventID", "EventID"))
    source_ip = _first_non_empty(
        flattened,
        (
            "EventData_Data_IpAddress",
            "System_EventData_Data_IpAddress",
            "System_EventData_IpAddress",
            "EventData_IpAddress",
            "IpAddress",
            "ClientIpAddress",
            "SourceIp",
        ),
    )
    status_code = _first_non_empty(
        flattened,
        (
            "EventData_Data_StatusCode",
            "System_EventData_Data_StatusCode",
            "System_EventData_StatusCode",
            "EventData_StatusCode",
            "StatusCode",
            "Status",
        ),
    )

    message = json.dumps(flattened, ensure_ascii=False, sort_keys=True)

    row: dict[str, Any] = {
        "timestamp": timestamp,
        "event": event_id,
        "message": message,
        "record_id": record.get("event_record_id", record.get("identifier")),
        "source_ip": source_ip,
        "status_code": status_code,
        "provider": flattened.get("System_Provider_Name"),
        "channel": flattened.get("System_Channel"),
        "computer": flattened.get("System_Computer"),
        "level": flattened.get("System_Level"),
        "task": flattened.get("System_Task"),
    }
    return {key: value for key, value in row.items() if value is not None}


def _write_evtx_records(
    parser: PyEvtxParser,
    writer: csv.DictWriter,
) -> None:
    """Parse EVTX records and write them as rows to the CSV writer.

    Raises RuntimeError when a record cannot be parsed.
    """
    records = parser.records_json()
    for record in records:
        if record is None:
            continue
        payload = record.get("data")
        if isinstance(payload, str):
            try:
                event_data: dict[str, Any] = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Unable to parse EVTX record {record.get('event_record_id', record.get('identifier'))}"
                ) from exc
        elif isinstance(payload, dict):
            event_data = payload
        else:
            event_data = {"raw": payload}

        if "Event" in event_data and set(event_data.keys()) == {"Event"}:
            event_data = event_data["Event"]

        writer.writerow(_extract_evtx_fields(event_data, record))


def load_evtx(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Convert an EVTX file into a temporary CSV and load it into DuckDB."""
    name = resolve_table_name(log_file, table_name)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir) / f"{name}.csv"
        with tmp_path.open("w", encoding="utf-8", newline="") as tmp:
            writer = csv.DictWriter(
                tmp,
                fieldnames=list(EVTX_CSV_FIELDNAMES),
                extrasaction="ignore",
            )
            writer.writeheader()

            parser = PyEvtxParser(str(log_file.path.resolve()))
            try:
                _write_evtx_records(parser, writer)
            except RuntimeError as exc:
                if "Unable to parse EVTX record" in str(exc):
                    raise
                raise RuntimeError(f"Unable to parse EVTX file {log_file.path}") from exc
            except Exception as exc:  # pragma: no cover - exercised through parser errors
                raise RuntimeError(f"Unable to parse EVTX file {log_file.path}") from exc

        connection.execute(
            f'CREATE OR REPLACE TABLE "{name}" AS SELECT * FROM read_csv_auto(?)',
            [str(tmp_path)],
        )

    return build_result(connection, name)


def iter_evtx_record_summaries(path: Path, max_records: int = 50) -> list[dict[str, Any]]:
    """Return lightweight per-record summaries for a UI preview.

    Each summary contains ``record_id``, ``timestamp``, ``event_id``,
    ``provider`` and ``channel`` extracted from the flattened EVTX payload.
    Parser/IO errors propagate to the caller.
    """
    parser = PyEvtxParser(str(path.resolve()))
    summaries: list[dict[str, Any]] = []
    for index, record in enumerate(parser.records_json()):
        if index >= max_records:
            break
        if record is None:
            continue
        payload = record.get("data")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}
        if isinstance(payload, dict) and set(payload.keys()) == {"Event"}:
            payload = payload["Event"]
        flattened = _flatten_event_payload(payload if isinstance(payload, dict) else {})
        summaries.append(
            {
                "record_id": record.get("event_record_id", record.get("identifier")),
                "timestamp": _first_non_empty(
                    flattened, ("System_TimeCreated_SystemTime", "TimeCreated_SystemTime", "timestamp")
                ),
                "event_id": _first_non_empty(flattened, ("System_EventID", "EventID")),
                "provider": flattened.get("System_Provider_Name"),
                "channel": flattened.get("System_Channel"),
            }
        )
    return summaries

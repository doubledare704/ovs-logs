"""DuckDB ingestion adapters for supported log formats."""

import csv
import json
import logging
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

import duckdb
from evtx import PyEvtxParser

from ovs_logs.config.settings import EVTXToolSettings, settings
from ovs_logs.core.constants import EVTX_CSV_FIELDNAMES, SINGLE_COLUMN_DELIMITER
from ovs_logs.core.errors import BinaryNotFoundError, IngestionError
from ovs_logs.core.models import LogFile
from ovs_logs.core.sql_utils import quote_identifier, resolve_table_name

type FilePath = str | Path
type DuckDBConn = duckdb.DuckDBPyConnection
type TableName = str | None
type EvtxAdapterFunc = Callable[[LogFile, DuckDBConn, TableName], IngestionResult]


@runtime_checkable
class EVTXEngine(Protocol):
    """Structural contract for an EVTX ingestion engine."""

    @property
    def name(self) -> str: ...

    def is_available(self) -> bool: ...

    def ingest(self, log_file: LogFile, output_path: Path) -> None: ...


@dataclass(frozen=True, slots=True)
class IngestionResult:
    """Represents the outcome of a successful log ingestion operation."""

    table_name: str
    row_count: int
    schema: Sequence[tuple[str, str]]

    @property
    def is_unstructured(self) -> bool:
        """Return True if the ingested table contains raw unstructured text."""
        return len(self.schema) == 1 and self.schema[0][0] == "line"


def build_result(connection: DuckDBConn, table_name: str) -> IngestionResult:
    """Query the loaded table for row count and schema."""
    quoted_name = quote_identifier(table_name)
    row = connection.execute(f"SELECT COUNT(*) FROM {quoted_name}").fetchone()
    row_count = int(row[0]) if row is not None else 0
    schema_rows = connection.execute(f"DESCRIBE {quoted_name}").fetchall()
    schema = [(row[0], row[1]) for row in schema_rows]
    return IngestionResult(table_name=table_name, row_count=row_count, schema=schema)


def is_hayabusa_available(evtx_settings: EVTXToolSettings | None = None) -> bool:
    """Check if the Hayabusa binary exists at the configured path."""
    s = evtx_settings or settings.evtx_tools
    return Path(s.hayabusa_path).is_file()


def run_evtx_tool(
    cmd: list[str],
    output_path: Path,
    tool_name: str,
    binary_path: str,
    timeout_seconds: int,
) -> None:
    """Run an external EVTX tool and validate that it produced output."""
    bin_path = Path(binary_path)
    if bin_path.is_absolute() and not bin_path.is_file():
        raise BinaryNotFoundError(f"{tool_name} binary not found: {binary_path}")

    try:
        result = subprocess.run(
            cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=timeout_seconds
        )
    except FileNotFoundError as exc:
        raise BinaryNotFoundError(f"{tool_name} binary not found: {binary_path}") from exc
    except PermissionError as exc:
        raise IngestionError(f"{tool_name} is not executable: {binary_path}") from exc
    except subprocess.CalledProcessError as exc:
        raise IngestionError(f"{tool_name} failed (exit {exc.returncode}): {exc.stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise IngestionError(f"{tool_name} timed out after {timeout_seconds}s") from exc

    if not output_path.is_file() or output_path.stat().st_size == 0:
        stderr = result.stderr.strip() if result.stderr else ""
        msg = f"{tool_name} produced no output at {output_path}"
        if stderr:
            msg += f"\n{tool_name} stderr:\n{stderr}"
        raise IngestionError(msg)


HayabusaFormat = Literal["csv", "json", "jsonl"]


def run_hayabusa_cli(
    log_file: LogFile,
    output_path: Path,
    evtx_settings: EVTXToolSettings,
    format: HayabusaFormat = "json",
) -> None:
    """Run the Hayabusa ``dfir-timeline`` subcommand, writing to *output_path*."""
    cmd = [
        evtx_settings.hayabusa_path,
        "dfir-timeline",
        "-t",
        format,
        "-f",
        str(log_file.path),
        "-r",
        evtx_settings.hayabusa_rules_dir,
        "-o",
        str(output_path),
        "-w",
    ]
    run_evtx_tool(
        cmd,
        output_path,
        "hayabusa",
        evtx_settings.hayabusa_path,
        evtx_settings.timeout_seconds,
    )


def load_csv_into_table(
    connection: DuckDBConn,
    name: str,
    csv_path: Path,
) -> IngestionResult:
    quoted_name = quote_identifier(name)
    connection.execute(
        f"CREATE OR REPLACE TABLE {quoted_name} AS SELECT * FROM read_csv_auto(?, header=true, all_varchar=true)",
        [str(csv_path)],
    )
    return build_result(connection, name)


def load_json_into_table(
    connection: DuckDBConn,
    name: str,
    json_path: Path,
) -> IngestionResult:
    quoted_name = quote_identifier(name)
    connection.execute(
        f"CREATE OR REPLACE TABLE {quoted_name} AS SELECT * FROM read_json_auto(?)",
        [str(json_path)],
    )
    return build_result(connection, name)


def load_csv(
    log_file: LogFile,
    connection: DuckDBConn,
    table_name: TableName = None,
) -> IngestionResult:
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
    connection: DuckDBConn,
    table_name: TableName = None,
) -> IngestionResult:
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
    connection: DuckDBConn,
    table_name: TableName = None,
) -> IngestionResult:
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


def _flatten_named_data_list(value: list[object]) -> dict[str, object] | None:
    """Collapse an EventData ``Data`` array into ``{Name: text}`` pairs.

    pyevtx-rs renders ``<Data Name="IpAddress">1.2.3.4</Data>`` as
    ``{"#attributes": {"Name": "IpAddress"}, "#text": "1.2.3.4"}``. Returns
    ``None`` when the list does not follow this shape so it is preserved
    verbatim (e.g. a list of plain scalar values).
    """
    if not value:
        return None
    named: dict[str, object] = {}
    for item in value:
        if not isinstance(item, dict):
            return None
        attributes = item.get("#attributes")
        if not isinstance(attributes, dict) or "Name" not in attributes:
            return None
        text = item.get("#text")
        named[attributes["Name"]] = text
    return named


def _flatten_event_payload(value: object, parent_key: str = "") -> dict[str, object]:
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
        flattened: dict[str, object] = {}
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


def _first_non_empty(flattened: dict[str, object], keys: Sequence[str]) -> object | None:
    """Return the first non-empty value among ``keys``, or ``None``."""
    return next(
        (flattened[key] for key in keys if key in flattened and flattened[key] not in (None, "")),
        None,
    )


def _extract_evtx_fields(event_data: dict[str, dict], record: dict[str, object]) -> dict[str, object]:
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

    row: dict[str, object] = {
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

        payload: str = record.get("data")
        try:
            event_data: dict[str, dict] = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Unable to parse EVTX record {record.get('event_record_id', record.get('identifier'))}"
            ) from exc

        event_data = event_data["Event"]
        writer.writerow(_extract_evtx_fields(event_data, record))


def _parse_evtx_to_csv(log_file: LogFile, csv_path: Path) -> None:
    """Parse EVTX records via PyEvtxParser and write to a CSV file."""
    with csv_path.open("w", encoding="utf-8", newline="") as tmp:
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
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"Unable to parse EVTX record data: {exc}") from exc


def load_evtx(
    log_file: LogFile,
    connection: DuckDBConn,
    table_name: TableName = None,
) -> IngestionResult:
    """Convert an EVTX file into a temporary CSV and load it into DuckDB."""
    name = resolve_table_name(log_file, table_name)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir) / f"{name}.csv"
        _parse_evtx_to_csv(log_file, tmp_path)
        connection.execute(
            f'CREATE OR REPLACE TABLE "{name}" AS SELECT * FROM read_csv_auto(?)',
            [str(tmp_path)],
        )
    return build_result(connection, name)


class PyEvtxEngine:
    """Raw EVTX parsing via PyEvtxParser producing a CSV file."""

    @property
    def name(self) -> str:
        return "raw"

    def is_available(self) -> bool:
        return True

    def ingest(self, log_file: LogFile, output_path: Path) -> None:
        _parse_evtx_to_csv(log_file, output_path)


class HayabusaEngine:
    """Sigma-rule alert scanning via the Hayabusa CLI binary."""

    def __init__(self, evtx_settings: EVTXToolSettings | None = None) -> None:
        self._settings = evtx_settings or settings.evtx_tools

    @property
    def name(self) -> str:
        return "alerts"

    def is_available(self) -> bool:
        return Path(self._settings.hayabusa_path).is_file()

    def ingest(self, log_file: LogFile, output_path: Path) -> None:
        run_hayabusa_cli(log_file, output_path, self._settings, format="json")


@dataclass(frozen=True, slots=True)
class EngineOutput:
    """Result of a single engine's file-level execution."""

    engine_name: str
    output_path: Path
    success: bool
    error: Exception | None = None


_CORRELATION_VIEW_NAME: str = "v_correlated_alerts"


def _create_correlation_view(
    connection: DuckDBConn,
    raw_table: str,
    alerts_table: str,
) -> None:
    """Create a SQL view joining hayabusa alerts with raw EVTX events."""
    quoted_raw = quote_identifier(raw_table)
    quoted_alerts = quote_identifier(alerts_table)
    quoted_view = quote_identifier(_CORRELATION_VIEW_NAME)
    connection.execute(
        f"CREATE OR REPLACE VIEW {quoted_view} AS\n"
        "SELECT\n"
        "    a.*,\n"
        "    r.message    AS raw_message,\n"
        "    r.source_ip  AS raw_source_ip,\n"
        "    r.status_code AS raw_status_code,\n"
        "    r.provider   AS raw_provider,\n"
        "    r.level      AS raw_level,\n"
        "    r.task       AS raw_task\n"
        f"FROM {quoted_alerts} a\n"
        f"LEFT JOIN {quoted_raw} r\n"
        "    ON  a.RecordID = r.record_id\n"
        "    AND a.Channel  = r.channel\n"
        "    AND a.Computer = r.computer\n"
        "    AND a.Timestamp = r.timestamp"
    )


@dataclass(frozen=True, slots=True)
class HybridIngestionResult(IngestionResult):
    """Result of a hybrid EVTX ingestion (raw events + Hayabusa alerts)."""

    hayabusa_result: IngestionResult | None = None
    hayabusa_executed: bool = False
    alerts_table_name: str | None = None


class HybridIngestionPipeline:
    """Orchestrates parallel execution of multiple EVTX ingestion engines.

    Open for extension: accepts any sequence of ``EVTXEngine`` implementations.
    Closed for modification: pipeline logic does not change when new engines
    are added.
    """

    def __init__(
        self,
        engines: Sequence[EVTXEngine],
        connection: DuckDBConn,
    ) -> None:
        self._engines = engines
        self._connection = connection

    def execute(
        self,
        log_file: LogFile,
        base_table_name: str,
    ) -> HybridIngestionResult:
        """Run all engines in parallel and load results into DuckDB."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            outputs = self._run_engines(log_file, Path(tmp_dir))
            return self._load_into_duckdb(base_table_name, outputs)

    # -- internal --------------------------------------------------------

    def _run_engines(
        self,
        log_file: LogFile,
        tmp_dir: Path,
    ) -> list[EngineOutput]:
        """Execute available engines in parallel via ThreadPoolExecutor."""
        available = [eng for eng in self._engines if eng.is_available()]
        if not available:
            return []

        outputs: list[EngineOutput] = []
        with ThreadPoolExecutor(
            max_workers=len(available),
            thread_name_prefix="evtx",
        ) as pool:
            future_map = {pool.submit(self._safe_ingest, eng, log_file, tmp_dir): eng for eng in available}
            for future in as_completed(future_map):
                outputs.append(future.result())
        return outputs

    @staticmethod
    def _safe_ingest(
        engine: EVTXEngine,
        log_file: LogFile,
        tmp_dir: Path,
    ) -> EngineOutput:
        """Run a single engine, catching exceptions into EngineOutput."""
        output_path = tmp_dir / f"{engine.name}.csv"
        try:
            engine.ingest(log_file, output_path)
            return EngineOutput(
                engine_name=engine.name,
                output_path=output_path,
                success=True,
            )
        except Exception as exc:
            logging.warning(
                "Engine '%s' failed: %s",
                engine.name,
                exc,
            )
            return EngineOutput(
                engine_name=engine.name,
                output_path=output_path,
                success=False,
                error=exc,
            )

    def _load_into_duckdb(
        self,
        base_table_name: str,
        outputs: list[EngineOutput],
    ) -> HybridIngestionResult:
        """Load successful engine outputs into DuckDB tables."""
        raw_output = self._find_output(outputs, "raw")
        if raw_output is None or not raw_output.success:
            raise IngestionError("Raw EVTX parsing failed; cannot continue")

        raw_table = f"{base_table_name}_raw"
        raw_result = load_csv_into_table(
            self._connection,
            raw_table,
            raw_output.output_path,
        )

        hayabusa_output = self._find_output(outputs, "alerts")
        hayabusa_result = None
        alerts_table = None
        if hayabusa_output is not None and hayabusa_output.success:
            alerts_table = f"{base_table_name}_alerts"
            try:
                quoted = quote_identifier(alerts_table)
                self._connection.execute(
                    f"CREATE OR REPLACE TABLE {quoted} AS SELECT * FROM read_json_auto(?)",
                    [str(hayabusa_output.output_path)],
                )
                hayabusa_result = build_result(self._connection, alerts_table)
            except Exception as exc:
                logging.warning(
                    "Failed to load Hayabusa alerts into DuckDB: %s",
                    exc,
                )
                alerts_table = None

        if hayabusa_result is not None and alerts_table is not None:
            try:
                _create_correlation_view(self._connection, raw_table, alerts_table)
            except duckdb.Error:
                logging.debug("Could not create correlation view (alerts table schema mismatch)")

        return HybridIngestionResult(
            table_name=raw_table,
            row_count=raw_result.row_count,
            schema=raw_result.schema,
            hayabusa_result=hayabusa_result,
            hayabusa_executed=hayabusa_result is not None,
            alerts_table_name=alerts_table,
        )

    @staticmethod
    def _find_output(outputs: list[EngineOutput], engine_name: str) -> EngineOutput | None:
        return next((o for o in outputs if o.engine_name == engine_name), None)


def ingest_evtx_hybrid(
    log_file: LogFile,
    connection: DuckDBConn,
    table_name: TableName = None,
) -> HybridIngestionResult:
    """Run PyEvtxParser and Hayabusa in parallel for comprehensive EVTX analysis.

    Always produces a ``{base}_raw`` table from PyEvtxParser.  When Hayabusa
    is installed and accessible, also produces a ``{base}_alerts`` table and
    a ``v_correlated_alerts`` view.  Failures in Hayabusa are logged and
    do not prevent the raw ingestion from completing.
    """
    base_name = resolve_table_name(log_file, table_name)
    engines: list[EVTXEngine] = [
        PyEvtxEngine(),
        HayabusaEngine(settings.evtx_tools),
    ]
    pipeline = HybridIngestionPipeline(engines=engines, connection=connection)
    return pipeline.execute(log_file, base_name)


def iter_evtx_record_summaries(path: Path, max_records: int = 50) -> list[dict[str, object]]:
    """Return lightweight per-record summaries for a UI preview.

    Each summary contains ``record_id``, ``timestamp``, ``event_id``,
    ``provider`` and ``channel`` extracted from the flattened EVTX payload.
    Parser/IO errors propagate to the caller.
    """
    parser = PyEvtxParser(str(path.resolve()))
    summaries: list[dict[str, object]] = []
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


def load_evtx_via_hayabusa(
    log_file: LogFile,
    connection: DuckDBConn,
    table_name: TableName = None,
) -> IngestionResult:
    """Load an EVTX file via the Hayabusa CLI binary (csv-timeline subcommand).

    Hayabusa outputs only events that match its Sigma rules as a CSV timeline.
    """
    name = resolve_table_name(log_file, table_name)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir) / f"{name}.csv"
        run_hayabusa_cli(log_file, tmp_path, settings.evtx_tools, format="csv")
        return load_csv_into_table(connection, name, tmp_path)


def load_evtx_via_hayabusa_json(
    log_file: LogFile,
    connection: DuckDBConn,
    table_name: TableName = None,
) -> IngestionResult:
    """Load an EVTX file via Hayabusa JSON timeline output."""
    name = resolve_table_name(log_file, table_name)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir) / f"{name}.json"
        run_hayabusa_cli(log_file, tmp_path, settings.evtx_tools, format="json")
        return load_json_into_table(connection, name, tmp_path)


EVTX_TOOL_ADAPTERS: dict[str, EvtxAdapterFunc] = {
    "default": load_evtx,
    "hayabusa": load_evtx_via_hayabusa,
    "hayabusa-json": load_evtx_via_hayabusa_json,
    "hybrid": ingest_evtx_hybrid,
}
"""Selectable EVTX processing tools mapped to their ingestion adapters."""

EVTX_TOOL_CHOICES: tuple[str, ...] = tuple(EVTX_TOOL_ADAPTERS)
"""Valid ``--tool`` values and sidebar options, in canonical order."""

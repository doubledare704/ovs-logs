"""DuckDB ingestion adapters for supported log formats."""

from __future__ import annotations

import csv
import logging
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from typing import Sequence

import duckdb

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


def _build_result(connection: duckdb.DuckDBPyConnection, table_name: str) -> LoadResult:
    """Query the loaded table for row count and schema."""
    row_count = connection.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()[0]
    schema_rows = connection.execute(f'DESCRIBE "{table_name}"').fetchall()
    schema = [(row[0], row[1]) for row in schema_rows]
    return LoadResult(table_name=table_name, row_count=row_count, schema=schema)


def load_csv(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Load a CSV file into DuckDB using ``read_csv_auto``."""
    name = _resolve_table_name(log_file, table_name)
    connection.execute(
        f'CREATE OR REPLACE TABLE "{name}" AS SELECT * FROM read_csv_auto(?)',
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
    connection.execute(
        f'CREATE OR REPLACE TABLE "{name}" AS SELECT * FROM read_json_auto(?)',
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
    connection.execute(f'CREATE OR REPLACE TABLE "{name}" (line VARCHAR)')
    logging.info(f'Loading text log into table "{name}" from {log_file.path}')
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".csv", delete=False, newline=""
        ) as tmp:
            writer = csv.writer(tmp)
            writer.writerow(["line"])
            with log_file.path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    writer.writerow([line.rstrip("\n")])
            tmp_path = tmp.name
            logging.info(f"Temporary CSV file created at {tmp_path} for ingestion")
        
        logging.info(f'Inserting data from temporary CSV into table "{name}"')
        connection.execute(
            f'INSERT INTO "{name}" SELECT * FROM read_csv_auto(?)',
            [tmp_path],
        )
    finally:
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return _build_result(connection, name)


def load_evtx(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str | None = None,
) -> LoadResult:
    """Placeholder for EVTX ingestion.

    Raises:
        NotImplementedError: EVTX conversion is not yet supported in the MVP.
    """
    raise NotImplementedError(
        f"EVTX ingestion is not yet implemented for {log_file.path}. "
        "The file is flagged as needing conversion (needs_conversion=True)."
    )

"""Service-layer orchestration for external EVTX tool workflows."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Literal

import duckdb

from ovs_logs.config.settings import EVTXToolSettings, Settings
from ovs_logs.core.ingestion.adapters import (
    IngestionResult,
    load_csv_into_table,
    load_json_into_table,
    run_evtx_tool,
)
from ovs_logs.core.validation import LogFile

HayabusaFormat = Literal["csv", "json", "jsonl"]

HAYABUSA_EXT_MAP: dict[HayabusaFormat, str] = {
    "csv": "csv",
    "json": "json",
    "jsonl": "jsonl",
}


def _run_hayabusa_timeline(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    settings: Settings,
    *,
    format: HayabusaFormat = "csv",
) -> IngestionResult:
    with tempfile.TemporaryDirectory() as tmp_dir:
        ext = HAYABUSA_EXT_MAP[format]
        tmp_path = Path(tmp_dir) / f"{table_name}.{ext}"
        cmd = [
            settings.evtx_tools.hayabusa_path,
            "dfir-timeline",
            "-t",
            format,
            "-f",
            str(log_file.path),
            "-r",
            settings.evtx_tools.hayabusa_rules_dir,
            "-o",
            str(tmp_path),
            "-w",
        ]
        run_evtx_tool(cmd, tmp_path, "hayabusa", settings.evtx_tools.hayabusa_path, settings.evtx_tools.timeout_seconds)
        if format == "csv":
            return load_csv_into_table(connection, table_name, tmp_path)
        return load_json_into_table(connection, table_name, tmp_path)


def _run_hayabusa_workflow(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    settings: Settings,
) -> IngestionResult:
    return _run_hayabusa_timeline(log_file, connection, table_name, settings, format="csv")


def _run_hayabusa_json_workflow(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    settings: Settings,
) -> IngestionResult:
    return _run_hayabusa_timeline(log_file, connection, table_name, settings, format="json")


def _run_hayabusa_json_to_file(
    log_file: LogFile,
    output_path: Path,
    evtx_settings: EVTXToolSettings,
) -> None:
    """Run Hayabusa JSON timeline, writing output to *output_path*."""
    cmd = [
        evtx_settings.hayabusa_path,
        "dfir-timeline",
        "-t",
        "json",
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

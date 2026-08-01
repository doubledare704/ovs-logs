"""Service-layer orchestration for external EVTX tool workflows."""

from __future__ import annotations

import tempfile
from pathlib import Path

import duckdb

from ovs_logs.config.settings import Settings
from ovs_logs.core.ingestion.adapters import (
    IngestionResult,
    load_csv_into_table,
    load_json_into_table,
    run_evtx_tool,
)
from ovs_logs.core.validation import LogFile


def _run_hayabusa_workflow(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    settings: Settings,
) -> IngestionResult:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir) / f"{table_name}.csv"
        cmd = [
            settings.evtx_tools.hayabusa_path,
            "csv-timeline",
            "-f",
            str(log_file.path),
            "-o",
            str(tmp_path),
            "-w",
        ]
        run_evtx_tool(cmd, tmp_path, "hayabusa", settings.evtx_tools.hayabusa_path, settings.evtx_tools.timeout_seconds)
        return load_csv_into_table(connection, table_name, tmp_path)


def _run_evtxecmd_workflow(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    settings: Settings,
) -> IngestionResult:
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_filename = f"{table_name}.csv"
        cmd = [
            settings.evtx_tools.evtxecmd_path,
            "-f",
            str(log_file.path),
            "--csv",
            str(tmp_dir),
            "--csvf",
            output_filename,
        ]
        output_path = Path(tmp_dir) / output_filename
        run_evtx_tool(
            cmd, output_path, "EvtxECmd", settings.evtx_tools.evtxecmd_path, settings.evtx_tools.timeout_seconds
        )
        return load_csv_into_table(connection, table_name, output_path)


def _run_hayabusa_json_workflow(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    settings: Settings,
) -> IngestionResult:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir) / f"{table_name}.json"
        cmd = [
            settings.evtx_tools.hayabusa_path,
            "json-timeline",
            "-f",
            str(log_file.path),
            "-o",
            str(tmp_path),
            "-w",
            "-L",
        ]
        run_evtx_tool(cmd, tmp_path, "hayabusa", settings.evtx_tools.hayabusa_path, settings.evtx_tools.timeout_seconds)
        return load_json_into_table(connection, table_name, tmp_path)


def _run_evtxecmd_json_workflow(
    log_file: LogFile,
    connection: duckdb.DuckDBPyConnection,
    table_name: str,
    settings: Settings,
) -> IngestionResult:
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_filename = f"{table_name}.json"
        cmd = [
            settings.evtx_tools.evtxecmd_path,
            "-f",
            str(log_file.path),
            "--json",
            str(tmp_dir),
            "--jsonf",
            output_filename,
        ]
        output_path = Path(tmp_dir) / output_filename
        run_evtx_tool(
            cmd, output_path, "EvtxECmd", settings.evtx_tools.evtxecmd_path, settings.evtx_tools.timeout_seconds
        )
        return load_json_into_table(connection, table_name, output_path)
